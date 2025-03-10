import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder

# 1. Extract rules from a Decision Tree
#    - If no conditions exist (root is a leaf), store "True"

def extract_rules(tree, feature_names):
    tree_ = tree.tree_
    feature_name = [
        feature_names[i] if i != -2 else "leaf" for i in tree_.feature
    ]
    rules = []

    def recurse(node, rule_parts):
        if tree_.feature[node] != -2:  # Not a leaf
            name = feature_name[node]
            threshold = tree_.threshold[node]
            left_rule = f"{name} <= {threshold:.2f}"
            right_rule = f"{name} > {threshold:.2f}"
            recurse(tree_.children_left[node], rule_parts + [left_rule])
            recurse(tree_.children_right[node], rule_parts + [right_rule])
        else:  # Leaf node
            class_pred = tree_.value[node].argmax()
            # If no conditions, treat as "True" rule
            rule_str = " and ".join(rule_parts) if rule_parts else "True"
            rules.append((rule_str, class_pred))
    
    recurse(0, [])
    return rules


# 2. Helper function to parse rule conditions
#    - Return (None, None, None) if condition is "True"

def parse_condition(condition):
    condition = condition.strip()
    # Handle unconditional rule
    if condition == "True":
        return None, None, None
    
    for op in ["<=", ">"]:
        if op in condition:
            feature, value = condition.split(op)
            return feature.strip(), op, value.strip()
    
    raise ValueError("Invalid condition format")


# 3. Modified IREP Implementation (selects the best pruned rule)
def irep_algorithm(X, y, feature_names, max_rules=10):
    # Split data into train (80%) and test (20%)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    # Further split train into grow/prune (67% / 33% of train)
    X_grow, X_prune, y_grow, y_prune = train_test_split(
        X_train, y_train, test_size=0.33, random_state=42
    )
    
    remaining_examples = X_grow.copy()
    remaining_labels = y_grow.copy()
    final_rules = []

    print("Starting IREP Algorithm...\n")
    
    while len(final_rules) < max_rules and len(remaining_examples) > 0:
        # Train a small decision tree
        tree = DecisionTreeClassifier(max_depth=3, random_state=42)
        tree.fit(remaining_examples, remaining_labels)
        
        # Extract candidate rules from the tree
        growing_rules = extract_rules(tree, feature_names)
        print("Growing Phase - Rules before pruning:")
        for rule, pred in growing_rules:
            print(f"  Rule: {rule} => Class {pred}")
        
        # -------------------------------------------
        # Pruning Phase
        # -------------------------------------------
        X_prune_df = pd.DataFrame(X_prune, columns=feature_names)
        # We'll collect all candidate pruned rules, then pick the best
        pruned_rules_candidates = []
        
        for rule, pred in growing_rules:
            conditions = rule.split(" and ")
            # Start with a mask covering all prune examples
            mask = np.ones(len(X_prune), dtype=bool)
            
            for cond in conditions:
                feature, operator, value = parse_condition(cond)
                # If feature is None => "True" rule => covers all examples
                if feature is None:
                    continue
                if operator == "<=":
                    mask &= X_prune_df[feature] <= float(value)
                else:  # operator == ">"
                    mask &= X_prune_df[feature] > float(value)
            
            coverage = mask.sum()
            if coverage > 0:
                y_prune_covered = y_prune[mask]
                # Error if we keep the rule
                error_unpruned = 1 - accuracy_score(y_prune_covered, [pred] * coverage)
                # Error if we prune the rule (replace with majority class)
                majority_class = pd.Series(y_prune).mode()[0]
                error_pruned = 1 - accuracy_score(y_prune_covered, [majority_class] * coverage)
                
                # Keep this rule if not worse than pruning
                if error_unpruned <= error_pruned:
                    pruned_rules_candidates.append((rule, pred, error_unpruned, coverage))
        
        # Sort pruned rules by their error_unpruned (ascending)
        pruned_rules_candidates.sort(key=lambda x: x[2])
        
        print("\nPruning Phase - Rules after pruning:")
        for (r_rule, r_pred, r_err, r_cov) in pruned_rules_candidates:
            print(f"  Rule: {r_rule} => Class {r_pred}, error={r_err:.4f}, coverage={r_cov}")
        
        # Pick the best rule from the pruned candidates (lowest error)
        if pruned_rules_candidates:
            best_rule, best_pred, best_error, best_cov = pruned_rules_candidates[0]
            final_rules.append((best_rule, best_pred))
            
            # Remove covered examples from the remaining_examples
            X_grow_df = pd.DataFrame(remaining_examples, columns=feature_names)
            mask = np.ones(len(X_grow_df), dtype=bool)
            
            for cond in best_rule.split(" and "):
                feature, operator, value = parse_condition(cond)
                # "True" rule => covers everything
                if feature is None:
                    continue
                if operator == "<=":
                    mask &= X_grow_df[feature] <= float(value)
                else:  # operator == ">"
                    mask &= X_grow_df[feature] > float(value)
            
            remaining_examples = remaining_examples[~mask]
            remaining_labels = remaining_labels[~mask]
        
        if not pruned_rules_candidates:
            # No valid pruned rule => stop
            break
    
    # -------------------------------------------
    # Evaluate on test set
    # -------------------------------------------
    X_test_df = pd.DataFrame(X_test, columns=feature_names)
    predictions = np.zeros(len(X_test), dtype=int)
    
    for i, row_data in X_test_df.iterrows():
        # Default prediction (if no rule matches) can be 0 or majority
        predictions[i] = 0  
        
        for rule, pred in final_rules:
            conditions = rule.split(" and ")
            satisfies_rule = True
            for cond in conditions:
                feature, operator, value = parse_condition(cond)
                # If feature is None => "True" => covers all
                if feature is None:
                    continue
                if operator == "<=":
                    if row_data[feature] > float(value):
                        satisfies_rule = False
                        break
                else:  # operator == ">"
                    if row_data[feature] <= float(value):
                        satisfies_rule = False
                        break
            if satisfies_rule:
                predictions[i] = pred
                break
    
    accuracy = accuracy_score(y_test, predictions)
    return final_rules, accuracy

# =====================================
#           MAIN SCRIPT
# =====================================
if __name__ == "__main__":
    # Load your full dataset
    # (Change the path/filename to match your real dataset)
    data = pd.read_csv('/content/cybersecurity_intrusion_data.csv')
    
    # 1. Drop Irrelevant Columns
    data.drop(columns=['session_id'], inplace=True)

    # 2. Encode Categorical Columns (if they exist)
    categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
    for col in categorical_cols:
        if col in data.columns:
            le = LabelEncoder()
            data[col] = le.fit_transform(data[col].astype(str))

    # 3. Define feature names & separate features/labels
    feature_names = [
        'network_packet_size',
        'protocol_type',
        'login_attempts',
        'session_duration',
        'encryption_used',
        'ip_reputation_score',
        'failed_logins',
        'browser_type',
        'unusual_time_access'
    ]
    X = data[feature_names].values
    y = data['attack_detected'].values

    # 4. Run IREP algorithm
    final_rules, final_accuracy = irep_algorithm(X, y, feature_names, max_rules=10)

    # 5. Print the final ruleset and accuracy
    print("\nFinal Ruleset:")
    for rule, pred in final_rules:
        print(f"  Rule: {rule} => Class {pred}")
    
    print(f"\nFinal Accuracy on Test Set: {final_accuracy:.4f}")
