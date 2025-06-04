export function calculateSHA512(left, right) {
    const combined = left + right;
    return sha512(combined);
}

export function displayMerklePath(merklePathData) {
    const container = document.getElementById('merkleContainer');
    container.innerHTML = '';

    let currentHash = merklePathData[0].Hash;

    merklePathData.forEach((node, index) => {
        const levelDiv = document.createElement('div');
        levelDiv.className = 'level';

        const hashCombination = document.createElement('div');
        hashCombination.className = 'hash-combination';

        // Текущий узел
        const currentNodeDiv = document.createElement('div');
        currentNodeDiv.className = 'node current-node';

        const currentDirectionDiv = document.createElement('div');
        currentDirectionDiv.className = 'direction';
        currentDirectionDiv.textContent = 'Текущий хеш';

        const currentHashDiv = document.createElement('div');
        currentHashDiv.className = 'hash';
        currentHashDiv.textContent = currentHash.substring(0, 20) + '...';

        currentNodeDiv.appendChild(currentDirectionDiv);
        currentNodeDiv.appendChild(currentHashDiv);

        // Добавляем узлы в правильном порядке
        if (index < merklePathData.length - 1) {
            if (!node.IsRight) {
                hashCombination.appendChild(currentNodeDiv);

                const hashContainer = document.createElement('div');
                hashContainer.className = 'hash-container';

                const arrow = document.createElement('div');
                arrow.className = 'hash-arrow';
                arrow.textContent = '→';

                const popupResult = document.createElement('div');
                popupResult.className = 'popup-result';
                const nextHash = calculateSHA512(currentHash, merklePathData[index + 1].Hash);
                popupResult.innerHTML = `
                    <div class="popup-title">Детали хеширования</div>
                    <div class="hash-details">Левый хеш: ${currentHash}</div>
                    <div class="hash-details">Правый хеш: ${merklePathData[index + 1].Hash}</div>
                    <div class="hash-details">Порядок объединения: ${currentHash} + ${merklePathData[index + 1].Hash}</div>
                    <div class="hash-details">Результат SHA-512:</div>
                    <div class="full-hash">${nextHash}</div>
                `;

                hashContainer.appendChild(arrow);
                hashContainer.appendChild(popupResult);
                hashCombination.appendChild(hashContainer);

                const siblingNode = document.createElement('div');
                siblingNode.className = 'node sibling-node';
                siblingNode.innerHTML = `
                    <div class="direction">Правый сосед</div>
                    <div class="hash">${merklePathData[index + 1].Hash.substring(0, 20)}...</div>
                `;
                hashCombination.appendChild(siblingNode);

                currentHash = nextHash;
            } else {
                const siblingNode = document.createElement('div');
                siblingNode.className = 'node sibling-node';
                siblingNode.innerHTML = `
                    <div class="direction">Левый сосед</div>
                    <div class="hash">${merklePathData[index + 1].Hash.substring(0, 20)}...</div>
                `;
                hashCombination.appendChild(siblingNode);

                const hashContainer = document.createElement('div');
                hashContainer.className = 'hash-container';

                const arrow = document.createElement('div');
                arrow.className = 'hash-arrow';
                arrow.textContent = '→';

                const popupResult = document.createElement('div');
                popupResult.className = 'popup-result';
                const nextHash = calculateSHA512(merklePathData[index + 1].Hash, currentHash);
                popupResult.innerHTML = `
                    <div class="popup-title">Детали хеширования</div>
                    <div class="hash-details">Левый хеш: ${merklePathData[index + 1].Hash}</div>
                    <div class="hash-details">Правый хеш: ${currentHash}</div>
                    <div class="hash-details">Порядок объединения: ${merklePathData[index + 1].Hash} + ${currentHash}</div>
                    <div class="hash-details">Результат SHA-512:</div>
                    <div class="full-hash">${nextHash}</div>
                `;

                hashContainer.appendChild(arrow);
                hashContainer.appendChild(popupResult);
                hashCombination.appendChild(hashContainer);

                hashCombination.appendChild(currentNodeDiv);

                currentHash = nextHash;
            }
        } else {
            // Последний узел (корневой хеш)
            const rootNode = document.createElement('div');
            rootNode.className = 'node root-node';
            rootNode.innerHTML = `
                <div class="direction">Корневой хеш</div>
                <div class="hash">${currentHash.substring(0, 20)}...</div>
            `;

            const hashContainer = document.createElement('div');
            hashContainer.className = 'hash-container';
            hashContainer.appendChild(rootNode);

            const popupResult = document.createElement('div');
            popupResult.className = 'popup-result';
            popupResult.innerHTML = `
                <div class="popup-title">Корневой хеш дерева Меркла</div>
                <div class="full-hash">${currentHash}</div>
            `;

            hashContainer.appendChild(popupResult);
            hashCombination.appendChild(hashContainer);
        }

        levelDiv.appendChild(hashCombination);

        if (index < merklePathData.length - 1) {
            const arrow = document.createElement('div');
            arrow.className = 'arrow';
            arrow.textContent = '↓';
            levelDiv.appendChild(arrow);
        }

        container.appendChild(levelDiv);
    });
}