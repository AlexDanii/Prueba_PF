# main_updated.py - Versión actualizada para LangGraph 1.2.11
import sys
import time
import random
from datetime import datetime
from typing import TypedDict, List, Dict, Any, Optional

# ============================================================
# IMPORTAR LANGGRAPH (VERSIÓN ACTUALIZADA)
# ============================================================

HAS_LANGGRAPH = False
try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.memory import MemorySaver
    HAS_LANGGRAPH = True
    print("✅ LangGraph encontrado - Usando modo grafo")
except ImportError as e:
    print(f"⚠️ LangGraph no disponible: {e}")
    print("   Usando modo secuencial (sin LangGraph)")

# ============================================================
# ESTADO
# ============================================================

class AttackState(TypedDict):
    target: str
    subdomains: List[str]
    open_ports: List[Dict[str, Any]]
    technologies: List[str]
    vulnerabilities: List[Dict[str, Any]]
    current_step: str
    next_actions: List[str]
    executed_actions: List[Dict[str, Any]]
    logs: List[str]
    session_id: str
    start_time: str
    report: str
    error: Optional[str]
    is_complete: bool

def create_initial_state(target: str) -> AttackState:
    return {
        "target": target,
        "subdomains": [],
        "open_ports": [],
        "technologies": [],
        "vulnerabilities": [],
        "current_step": "inicio",
        "next_actions": [],
        "executed_actions": [],
        "logs": [],
        "session_id": f"pentest-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "start_time": datetime.now().isoformat(),
        "report": "",
        "error": None,
        "is_complete": False
    }

# ============================================================
# NODOS - TODOS LOS NODOS DEL SISTEMA
# ============================================================

def run_recon(state):
    timestamp = datetime.now().strftime("%H:%M:%S")
    state["logs"].append(f"[{timestamp}] 🔍 Iniciando Reconocimiento")
    
    # Simulación de reconocimiento
    state["subdomains"] = [
        f"www.{state['target']}",
        f"api.{state['target']}",
        f"admin.{state['target']}",
        f"dev.{state['target']}",
        f"mail.{state['target']}"
    ]
    state["open_ports"] = [
        {"port": 80, "service": "http", "version": "nginx/1.18.0", "state": "open"},
        {"port": 443, "service": "https", "version": "nginx/1.18.0", "state": "open"},
        {"port": 22, "service": "ssh", "version": "OpenSSH 7.9", "state": "open"},
        {"port": 8080, "service": "tomcat", "version": "9.0.31", "state": "open"},
        {"port": 3306, "service": "mysql", "version": "8.0.23", "state": "filtered"}
    ]
    state["technologies"] = [
        "nginx/1.18.0", 
        "OpenSSH 7.9", 
        "Apache Tomcat 9.0.31", 
        "PHP 7.4.33",
        "WordPress 5.8"
    ]
    
    state["logs"].append(f"[{timestamp}] ✅ {len(state['subdomains'])} subdominios, {len(state['open_ports'])} puertos")
    state["logs"].append(f"[{timestamp}]    Tecnologías: {', '.join(state['technologies'][:3])}")
    return state

def run_scan(state):
    timestamp = datetime.now().strftime("%H:%M:%S")
    state["logs"].append(f"[{timestamp}] 🛡️ Iniciando Escaneo de Vulnerabilidades")
    
    vulns = []
    
    # Simular vulnerabilidades basadas en puertos y tecnologías
    if any(p["port"] == 8080 and "tomcat" in p["service"] for p in state["open_ports"]):
        vulns.append({
            "id": "CVE-2022-22947",
            "name": "Spring Boot Actuator Exposure (RCE)",
            "severity": "Critical",
            "port": 8080,
            "service": "tomcat",
            "exploitable": True,
            "cve_score": 9.8,
            "description": "Spring Boot Actuator expuesto sin autenticación, permite ejecución remota de código"
        })
    
    if any(p["port"] == 22 for p in state["open_ports"]):
        vulns.append({
            "id": "MISCONFIG-001",
            "name": "SSH Password Authentication Enabled",
            "severity": "High",
            "port": 22,
            "service": "ssh",
            "exploitable": True,
            "cve_score": 7.5,
            "description": "Permite autenticación por contraseña, vulnerable a ataques de fuerza bruta"
        })
    
    if any(p["port"] == 80 and "nginx" in p["service"] for p in state["open_ports"]):
        vulns.append({
            "id": "OWASP-TOP-1",
            "name": "Missing Security Headers",
            "severity": "Medium",
            "port": 80,
            "service": "nginx",
            "exploitable": False,
            "cve_score": 5.3,
            "description": "Faltan headers de seguridad (X-Frame-Options, CSP, HSTS)"
        })
    
    if any("wordpress" in tech.lower() for tech in state["technologies"]):
        vulns.append({
            "id": "CVE-2021-29447",
            "name": "WordPress XML-RPC Brute Force",
            "severity": "High",
            "port": 80,
            "service": "wordpress",
            "exploitable": True,
            "cve_score": 7.8,
            "description": "XML-RPC permite ataques de fuerza bruta y DDoS"
        })
    
    state["vulnerabilities"] = vulns
    
    critical = sum(1 for v in vulns if v["severity"] == "Critical")
    high = sum(1 for v in vulns if v["severity"] == "High")
    medium = sum(1 for v in vulns if v["severity"] == "Medium")
    
    state["logs"].append(f"[{timestamp}] ✅ {len(vulns)} vulnerabilidades encontradas")
    state["logs"].append(f"[{timestamp}]    Críticas: {critical}, Altas: {high}, Medias: {medium}")
    
    for vuln in vulns:
        state["logs"].append(f"[{timestamp}]    - {vuln['name']} ({vuln['severity']})")
    
    return state

def run_plan(state):
    timestamp = datetime.now().strftime("%H:%M:%S")
    state["logs"].append(f"[{timestamp}] 🧠 Planificando siguiente acción")
    
    actions = []
    
    # Priorizar vulnerabilidades críticas y explotables
    exploitable = [v for v in state["vulnerabilities"] if v.get("exploitable", False)]
    exploitable.sort(key=lambda x: x.get("cve_score", 0), reverse=True)
    
    for vuln in exploitable[:2]:
        if vuln["severity"] == "Critical":
            actions.append(f"EXPLOIT_CRITICAL:{vuln['id']}:{vuln['name']}")
        else:
            actions.append(f"EXPLOIT:{vuln['id']}:{vuln['name']}")
    
    if not actions:
        actions.append("ANALYZE:Enumeración de directorios")
        actions.append("ANALYZE:Análisis de parámetros HTTP")
    
    actions.append("REPORT:Generar informe final")
    
    state["next_actions"] = actions
    state["logs"].append(f"[{timestamp}] ✅ {len(actions)} acciones planificadas")
    
    for action in actions:
        state["logs"].append(f"[{timestamp}]    - {action}")
    
    return state

def run_execute(state):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if not state["next_actions"]:
        state["logs"].append(f"[{timestamp}] ⚠️ No hay acciones pendientes")
        return state
    
    action = state["next_actions"].pop(0)
    state["logs"].append(f"[{timestamp}] ⚡ Ejecutando: {action}")
    
    result = {
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "status": "pending"
    }
    
    if "EXPLOIT" in action:
        time.sleep(0.5)
        success_rate = 0.8 if "CRITICAL" in action else 0.6
        success = random.random() < success_rate
        
        if success:
            result["status"] = "success"
            vuln_id = action.split(":")[1] if len(action.split(":")) > 1 else "unknown"
            result["output"] = f"✅ Vulnerabilidad {vuln_id} explotada con éxito"
            result["evidence"] = {
                "type": "shell_access",
                "detail": f"Acceso obtenido a {state['target']}",
                "proof": f"Archivo /tmp/pwned_{vuln_id}.txt creado"
            }
            state["logs"].append(f"[{timestamp}] ✅ Explotación exitosa: {vuln_id}")
        else:
            result["status"] = "failed"
            result["output"] = f"❌ Explotación fallida"
            result["error"] = "Payload no compatible o servicio parcheado"
            state["logs"].append(f"[{timestamp}] ❌ Explotación fallida")
    
    elif "ANALYZE" in action:
        time.sleep(0.3)
        result["status"] = "success"
        analysis_type = action.split(":")[1] if len(action.split(":")) > 1 else "general"
        result["output"] = f"✅ Análisis {analysis_type} completado"
        result["findings"] = [
            "Endpoint adicional encontrado: /api/v2/",
            "Parámetros vulnerables detectados: id, file",
            "Backup expuesto: /backup/2024/"
        ]
        state["logs"].append(f"[{timestamp}] ✅ Análisis completado: {len(result['findings'])} hallazgos")
    
    elif "REPORT" in action:
        result["status"] = "success"
        result["output"] = "Preparando generación de reporte..."
        state["logs"].append(f"[{timestamp}] 📄 Preparando generación de reporte")
    
    state["executed_actions"].append(result)
    return state

def run_report(state):
    timestamp = datetime.now().strftime("%H:%M:%S")
    state["logs"].append(f"[{timestamp}] 📄 Generando reporte final")
    
    total_vulns = len(state["vulnerabilities"])
    critical_vulns = sum(1 for v in state["vulnerabilities"] if v.get("severity") == "Critical")
    high_vulns = sum(1 for v in state["vulnerabilities"] if v.get("severity") == "High")
    medium_vulns = sum(1 for v in state["vulnerabilities"] if v.get("severity") == "Medium")
    low_vulns = sum(1 for v in state["vulnerabilities"] if v.get("severity") == "Low")
    
    report = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    INFORME DE SEGURIDAD                         ║
╚══════════════════════════════════════════════════════════════════╝

SESIÓN: {state['session_id']}
OBJETIVO: {state['target']}
FECHA: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
DURACIÓN: {datetime.now() - datetime.fromisoformat(state['start_time'])}

═══════════════════════════════════════════════════════════════════
RESUMEN EJECUTIVO
═══════════════════════════════════════════════════════════════════

Total de vulnerabilidades: {total_vulns}
  • CRÍTICAS: {critical_vulns}
  • ALTAS: {high_vulns}
  • MEDIAS: {medium_vulns}
  • BAJAS: {low_vulns}

═══════════════════════════════════════════════════════════════════
VULNERABILIDADES DETECTADAS
═══════════════════════════════════════════════════════════════════
"""
    
    for vuln in state["vulnerabilities"]:
        severity_color = "🔴" if vuln.get("severity") == "Critical" else "🟡" if vuln.get("severity") == "High" else "🟢"
        report += f"""
{severity_color} [{vuln.get('severity', 'Unknown')}] {vuln.get('name', 'N/A')}
    ID: {vuln.get('id', 'N/A')}
    Puerto: {vuln.get('port', 'N/A')}
    Servicio: {vuln.get('service', 'N/A')}
    CVSS Score: {vuln.get('cve_score', 'N/A')}
    Descripción: {vuln.get('description', 'N/A')}
    Explotable: {'✅ Sí' if vuln.get('exploitable', False) else '❌ No'}
"""
    
    report += """
═══════════════════════════════════════════════════════════════════
ACCIONES EJECUTADAS
═══════════════════════════════════════════════════════════════════
"""
    
    for i, action in enumerate(state["executed_actions"], 1):
        status_icon = "✅" if action.get('status') == 'success' else "❌"
        report += f"{i}. {status_icon} {action.get('action', 'N/A')} - {action.get('status', 'N/A')}\n"
        if action.get('evidence'):
            report += f"   Evidencia: {action['evidence']}\n"
    
    report += """
═══════════════════════════════════════════════════════════════════
RECOMENDACIONES DE SEGURIDAD
═══════════════════════════════════════════════════════════════════

1. Actualizar Spring Boot a versión > 2.5.12 (corrige CVE-2022-22947)
2. Deshabilitar autenticación por contraseña en SSH (usar llaves)
3. Implementar headers de seguridad en Nginx
4. Deshabilitar XML-RPC en WordPress
5. Realizar pruebas de penetración adicionales
6. Implementar WAF (Web Application Firewall)

═══════════════════════════════════════════════════════════════════
FIN DEL REPORTE
═══════════════════════════════════════════════════════════════════
"""
    
    state["report"] = report
    state["is_complete"] = True
    state["logs"].append(f"[{timestamp}] ✅ Reporte generado exitosamente")
    return state

# ============================================================
# FUNCIONES DE EJECUCIÓN
# ============================================================

def run_flow_sequential(state):
    """Ejecuta el flujo en modo secuencial (sin LangGraph)"""
    print("  ▶ Reconocimiento...")
    state = run_recon(state)
    
    print("  ▶ Escaneo de vulnerabilidades...")
    state = run_scan(state)
    
    print("  ▶ Planificación...")
    state = run_plan(state)
    
    action_count = 0
    while state.get("next_actions") and len(state["next_actions"]) > 0:
        next_action = state["next_actions"][0] if state["next_actions"] else ""
        if next_action.startswith("REPORT"):
            break
        action_count += 1
        print(f"  ▶ Ejecutando acción {action_count}...")
        state = run_execute(state)
    
    print("  ▶ Generando reporte...")
    state = run_report(state)
    return state

def run_flow_langgraph(state):
    """Ejecuta el flujo usando LangGraph con la API actualizada"""
    if not HAS_LANGGRAPH:
        return run_flow_sequential(state)
    
    try:
        # Crear grafo - API actualizada para LangGraph 1.x
        workflow = StateGraph(AttackState)
        
        # Añadir nodos
        workflow.add_node("recon", run_recon)
        workflow.add_node("scan", run_scan)
        workflow.add_node("plan", run_plan)
        workflow.add_node("execute", run_execute)
        workflow.add_node("report", run_report)
        
        # Definir flujo
        workflow.set_entry_point("recon")
        workflow.add_edge("recon", "scan")
        workflow.add_edge("scan", "plan")
        
        # Función de decisión condicional
        def decide_next(state):
            if state.get("error"):
                return "end"
            if state.get("is_complete"):
                return "end"
            if state.get("next_actions"):
                next_action = state["next_actions"][0] if state["next_actions"] else ""
                if next_action.startswith("REPORT"):
                    return "report"
                return "execute"
            return "report" if state.get("vulnerabilities") else "end"
        
        workflow.add_conditional_edges("plan", decide_next, {
            "execute": "execute",
            "report": "report",
            "end": END
        })
        
        workflow.add_edge("execute", "plan")
        workflow.add_edge("report", END)
        
        # Compilar con MemorySaver para persistencia
        memory = MemorySaver()
        app = workflow.compile(checkpointer=memory)
        
        # Ejecutar
        final_state = None
        for event in app.stream(state, {"configurable": {"thread_id": "1"}}):
            for node_name, node_state in event.items():
                node_display = {
                    'recon': '🔍 Reconocimiento',
                    'scan': '🛡️ Escaneo',
                    'plan': '🧠 Planificación',
                    'execute': '⚡ Ejecución',
                    'report': '📄 Reporte'
                }
                print(f"  ▶ {node_display.get(node_name, node_name)}")
                final_state = node_state
        
        return final_state
        
    except Exception as e:
        print(f"  ⚠️ Error en LangGraph: {e}")
        print("  🔄 Cambiando a modo secuencial...")
        return run_flow_sequential(state)

# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("🛡️ SISTEMA DE PENTESTING AUTÓNOMO")
    print("=" * 60)
    print(f"📦 Modo: {'LangGraph' if HAS_LANGGRAPH else 'Secuencial'}")
    print("=" * 60)
    
    target = input("🌐 Objetivo (dominio/IP): ").strip()
    if not target:
        target = "ejemplo.com"
        print(f"⚠️ Usando objetivo por defecto: {target}")
    
    state = create_initial_state(target)
    print(f"\n🚀 Iniciando pentesting contra: {target}")
    print("-" * 60)
    
    try:
        if HAS_LANGGRAPH:
            print("🔄 Usando LangGraph para orquestación...")
            final_state = run_flow_langgraph(state)
        else:
            print("🔄 Usando modo secuencial...")
            final_state = run_flow_sequential(state)
        
        if final_state:
            print("\n" + "=" * 60)
            print("✅ PROCESO COMPLETADO")
            print("=" * 60)
            
            print(f"\n📊 Resumen:")
            print(f"  • Sesión: {final_state['session_id']}")
            print(f"  • Objetivo: {final_state['target']}")
            print(f"  • Vulnerabilidades: {len(final_state['vulnerabilities'])}")
            print(f"  • Acciones ejecutadas: {len(final_state['executed_actions'])}")
            
            print("\n📝 LOGS:")
            for log in final_state["logs"][-10:]:
                print(f"  {log}")
            
            if final_state.get("report"):
                print("\n" + final_state["report"])
            
            print("\n✅ ¡Listo!")
        else:
            print("\n❌ Error: No se recibió estado final")
    
    except KeyboardInterrupt:
        print("\n\n⚠️ Proceso interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()