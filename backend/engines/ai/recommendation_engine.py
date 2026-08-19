from typing import List, Dict, Any
from backend.engines.ai.models import AnalysisModel
from backend.engines.ai.templates import get_playbook
from backend.engines.ai.mitre import get_mitre_mapping

class AIRecommendationEngine:
    def generate_recommendations(self, model: AnalysisModel) -> List[Dict[str, Any]]:
        all_actions = []
        for attack in model.active_attack_types:
            playbook = get_playbook(attack)
            for action in playbook:
                all_actions.append((action, attack))
            
        if not all_actions:
            # If no threats, use default playbook (e.g. baseline checking)
            playbook = get_playbook("default")
            for action in playbook:
                all_actions.append((action, "default"))
            
        # Deduplicate and parse
        seen = set()
        deduped = []
        for action_str, source in all_actions:
            priority = 9
            action = action_str
            if action_str.startswith("Priority "):
                try:
                    parts = action_str.split(":", 1)
                    priority = int(parts[0].split(" ")[1])
                    action = parts[1].strip()
                except Exception:
                    pass
            
            if action not in seen:
                seen.add(action)
                deduped.append({
                    "priority": priority,
                    "action": action,
                    "source": source
                })
                
        # Sort by priority
        prioritized = sorted(deduped, key=lambda x: x["priority"])
        return prioritized

    def generate_mitre_details(self, model: AnalysisModel) -> List[Dict[str, str]]:
        mitre_list = []
        for attack in model.active_attack_types:
            mapping = get_mitre_mapping(attack)
            if mapping not in mitre_list:
                mitre_list.append(mapping)
        return mitre_list
