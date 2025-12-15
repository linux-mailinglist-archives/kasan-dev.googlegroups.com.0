Return-Path: <kasan-dev+bncBCJ455VFUALBBG7L77EQMGQECVX7KFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 74ECCCBD977
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:48:45 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-65742f8c565sf5697990eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:48:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765799324; cv=pass;
        d=google.com; s=arc-20240605;
        b=K4Pfb8j5FhDMrdFI3xsrPJ2bLfPjNy2a1h0hnqXqa0UiZkB8TgrgKoMnHJK1dACcR9
         M8aFoiOPun4/nFrVv1YHN/sLEYzYMGyqoNJlSAUL9h0V+FLobp0rO0gE8b3yqiUzDsFX
         +spvKStnnmBncwPi8Sh36f6xj5dqpUJbYgtCxXWr/YAuv/vba1r3TcOsLJtzMbuEq3Vl
         d7nMTXCDmffWhuCR/b5FZjg5P1XhFGLqllYbqqHV7pHnqVwqGDw5D0SeK/ekiz+TLBLT
         w12BoZ8+ZIwAwCUG6DzHra0iLnmB3Ub+FoBKzn9MNn4Z73tXiu7uV/sf+GqGpU8z/Ngn
         2Ztg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=jBv1okrRdr5JckJ1NmOdooCrHtz1nvHQcdwpHcklWeE=;
        fh=IHo8MDerj6n9N+oWJ/MA0xTlViVFWf4KCGmikp17/ks=;
        b=Ysn2o7/HerrkOtFUwCE5uWVKKahEPDdzrx8XMX0INo+KwEGXrus7ZfiDTTIFkYFyrL
         UY/PsBECorosA/NQ/cSgyFWYQhAM5usWEvzJD2hWNkkjLyqSMtLacQ62YK9zAPG8ciKP
         YzEZ4kjYYG+aF19pNSCwRX6azU8OQr8NjnpXCS7//CMeGTHjHGZ63+d2Si00dguOJOGp
         Iu2PYlPc7/DyCbtvO3Gq3iKnq0x7rPz48cwi7PbM4NO1GSGVZyjkFY6lR5riFDMk3OEH
         jBlYRsAaMp+ULdibkqBIabQXyPAV+IJTUYB1XdOjuRNO8G5ZXH7WWbUaT7XG0uQEedw2
         dfLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=heeo3ili;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765799324; x=1766404124; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jBv1okrRdr5JckJ1NmOdooCrHtz1nvHQcdwpHcklWeE=;
        b=GC7U6Hb6SSjs2DmTpVpHWvK9T57hP/Nswlu6t7gE8Ac8RVzo50b8NVnF/2mH7fghnn
         8twF51viTcRPyZMioxaa8Fkbnm9MnTw1Q8vTLzhjiMHkzWujWSNn5uRHsdhGN3+zLewE
         T30SCx+PKpcbVEPgkK2YbifcilWEnMT6+nJrskrtTAD77Qf9iZ/Tzg/RAAWfACNJ1p0X
         /gRlT5PEoRwZ0D0Woh2T19617Kjt6XKak0mGkrVer/sBmnM4tmHWcWbdd3+t5T8VZTnn
         nTCkNclZd//W0a6/4sMqpzq9kV7ZmMyZ6bAFqf5F/jJzaDA91pleeAmpUy51hrgyNdTE
         Umnw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765799324; x=1766404124; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=jBv1okrRdr5JckJ1NmOdooCrHtz1nvHQcdwpHcklWeE=;
        b=gvKM2rrB0cDS4qy0jo225sPNCkjyeHzyQbX5rVNPHGmlA6ECN+8zlJBAEa3pyy2l4x
         XEcHgKU4D2lNzVvKLLvnY/gX9MSDLYQu8j5s1VeyqaNzxEY9ifk4jBkalwaDFcvz9e2h
         fLK4wWDFoqT9vwL0KJb1q4rYL0BanfmXPRk0UW8Sj91LcURDuPlFB6fmQbHxwbpp0MX/
         axvcDxgSb+szXhsCAkysyUHFeQ9VpXKoa+ZypKLBq741lofZG49ie6qcDynMCKN8iBiB
         rnbq2QI07YsUeME974lE3DTpV6A5JBJcWuyg1pkJE354f+moCfNvJvVDlCI0X+f6hnIh
         CipQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765799324; x=1766404124;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jBv1okrRdr5JckJ1NmOdooCrHtz1nvHQcdwpHcklWeE=;
        b=fxjrJ2SaBV9ZpgANHVMDkS2t5GPS9zkpYEI1kgREHbcjqRt6yMcMR5vnkFMItvzpzT
         WkZL6ks6xPfj/xajScxXp1mHCesUgZlpVeIJzRHYRmc7sAjxVZLLDfAs/UFvi+NyIzSX
         AB11W8cn1hTgfCNzBvIol5OcmWuS+4DnGuFc7jqHkH/bxudjxIz9QJhFkVdk+iFBb/pb
         7Aj8X585LH5lYJLsDoqxdrXBwXbtnD2JM4+Y/pxoPtzERLYubatv5fepUODLPXGHwjlF
         51ZBc7mtgh1Vf02SHEA9/br7X/suQ0hG7zXajkfTE5D4uK8M5tnG0/9GtA3w7fKerdEV
         q5uQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWepqfNDezG736ySae2fe+KMT/Ca6CnBbnfYQeWrXtqQh9x0UEUVOfkKBnoCVhmGhKvU0zBtQ==@lfdr.de
X-Gm-Message-State: AOJu0YxptcYj6ax5q6H5TNOeh4gtyb15i18Y9zJaAN3X6nlsVZd1pMvF
	8wPfnwXrup52NczlanRagIyouibG9t14X/MbjArdYG8YiC4VYHSAv25s
X-Google-Smtp-Source: AGHT+IGOLSCrhusm0qj+OrhVGRFMvfrRY+rF+9ZWhT9G8PJzXxVWAYrfsDXcFKTAeNIVYFwlBrKweA==
X-Received: by 2002:a05:6820:1c89:b0:659:9a49:8fb8 with SMTP id 006d021491bc7-65b452575b8mr4881781eaf.49.1765799324008;
        Mon, 15 Dec 2025 03:48:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb3dIjVOTk3daCg25p2zM0sdjNj9A58Mzy+AP+RRTiQZA=="
Received: by 2002:a4a:e4c7:0:b0:657:5773:7b1d with SMTP id 006d021491bc7-65b439bd958ls1640660eaf.2.-pod-prod-05-us;
 Mon, 15 Dec 2025 03:48:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXxUYUOz7qd9p5wC/423AbOUdBOuSoTIkKhFjIQCoMX+SCpZE1d2oa+iqim1lCgU9sAHnpD3NZmLI=@googlegroups.com
X-Received: by 2002:a05:6830:6d9a:b0:79d:eccc:96eb with SMTP id 46e09a7af769-7cae8364daemr5114039a34.26.1765799323053;
        Mon, 15 Dec 2025 03:48:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765799323; cv=none;
        d=google.com; s=arc-20240605;
        b=OBbWK8jRPXRte869lWSeJgnrAMCq8lu+IeO7VG4tnd6lpKC/1fpxYWsu45W9VbKWzA
         PufdqKb7gyKvgMSqpMQtCuAYzldk6JwI3rzfHUnxCKMhAVqh4GY8y9V87ORmI7UudWg1
         viDJxYEe4CKyLLW/N3s0Zz7VAmIwrHfHYOQzyWvif7cM0MOEVBEUhtNet9eRgrIwftpA
         +NHXXr2z7lc8bozLTsVB0xgjMifPIBOAetlAoaRHyTbn8+qEhMuOsffTLNzAvPC8692a
         eWvxADHyMzRIRMBHBg5EDRgxnJNfJ2kSP8rJq3QkaCtH+XwqSXUmivWCRhfxgvVEvhZH
         FOBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8E8ZSVvZ3A1H5XIeWol9WzN+P6GbKkkMDrw9AgBsXoI=;
        fh=m55aIa0XD8AD5YUbevTJUY7pUgCWu+mNYMUUdNPPV8E=;
        b=KbkR8E9XnXtze1ktbM8DMlKD9oHRTYudgbVX4jtoAnspudn97nOLBmkIrYreYFRVhz
         +8++cRPwq5hTsivfOAEOvpOsmtxFzPXXzSD6GfJDbvd2v2hVfStK1sAxsaGIiAZ5pPg5
         1UGUJt1YcAje/oPscjQCe6kjUs6u32PWX6l8HKc6GbojDF+ZYcG71BwjhMcE5NrHeVJA
         h/whHNGrY1IIBhDsksUOfy2SCoyox9VnyVj37j+JcGi+Z8YnPGDvkZwJ2FCLnSLGEj9O
         cfY0VBR3UUoOjvPrBF2aL0itrN1MuBtFdOS2mlEdBEIAbfb3dk1nDJZxOWBlYzHYl6zf
         0BLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=heeo3ili;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cadb2cec87si614900a34.6.2025.12.15.03.48.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:48:43 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-2a0d67f1877so12375845ad.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:48:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXfRtoNOb50zCs62SnahVy1dEr6QDtK2kyqY8fOHdJxaYsVjB5ualPZeYXc+jJuxNlcIMa3dCtzyYU=@googlegroups.com
X-Gm-Gg: AY/fxX7jfWL7fQj/C2J+DEE4BAtE71Sf4NWUmBzQOVuPI4DWrnSJEqPgfTaTxZnbKeh
	iXzC9fn6pfj0QUfUUQEn6YHCGznT1Jgv/iL424V0czwb247zyh8og3ubEFUytkuCOXKiswKDg78
	JyoBVCeoRZfZAe9fyQE1ueQCjXAazlH5TcvOrT2R4bIbJSJKpe3wiR/uKS5mcXP47jgeQ0sUaai
	ZGr4QHVChONiw6bj45K1vAde4X43Md1AHK/sMLA8gZzB+HcqlkeXq2aew5sKWTsKk12QzzcS+iB
	HtOrWyWvgOWAMLKdLWctw62Gni5ChkdIw9CVc3pyNoWtrPcuJbtN0tcsZRi7bmer5SZQlyPNky+
	EkOJ2Yw+1A3AGCqTPJC9XVWY4z1E1bv6El3J4fSp6/XQkjVPjL8pxqbiDrcfTQE8GWM18R2oAIR
	LZjtVxVmRZg2I=
X-Received: by 2002:a17:903:1211:b0:295:5945:2920 with SMTP id d9443c01a7336-29f23c7bf9emr112051185ad.34.1765799322525;
        Mon, 15 Dec 2025 03:48:42 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a0be984c7csm47483205ad.66.2025.12.15.03.48.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:48:41 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 711C5447330D; Mon, 15 Dec 2025 18:39:07 +0700 (WIB)
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org,
	kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>
Cc: Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>,
	Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>,
	Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	Ido Schimmel <idosch@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>,
	Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>,
	Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	David Hildenbrand <david@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Max Kellermann <max.kellermann@ionos.com>,
	"Nysal Jan K.A." <nysal@linux.ibm.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexey Skidanov <alexey.skidanov@intel.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Vitaly Wool <vitaly.wool@konsulko.se>,
	Harry Yoo <harry.yoo@oracle.com>,
	Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>,
	Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>,
	Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>,
	YiPeng Chai <YiPeng.Chai@amd.com>,
	Hawking Zhang <Hawking.Zhang@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Daniel Almeida <daniel.almeida@collabora.com>,
	Luben Tuikov <luben.tuikov@amd.com>,
	Matthew Auld <matthew.auld@intel.com>,
	Roopa Prabhu <roopa@cumulusnetworks.com>,
	Mao Zhu <zhumao001@208suo.com>,
	Shaomin Deng <dengshaomin@cdjrlc.com>,
	Charles Han <hanchunchao@inspur.com>,
	Jilin Yuan <yuanjilin@cdjrlc.com>,
	Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
	George Anthony Vernon <contact@gvernon.com>
Subject: [PATCH 14/14] net: bridge: Describe @tunnel_hash member in net_bridge_vlan_group struct
Date: Mon, 15 Dec 2025 18:39:02 +0700
Message-ID: <20251215113903.46555-15-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=895; i=bagasdotme@gmail.com; h=from:subject; bh=Q9RPGjCwe41o18D04IVKznpQEFsNHpWb2BdI9cEOKh8=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n0POW63OZ/vV5HO1nI0n8+fcu08SpWN+KD02YL721 ObASlnjjlIWBjEuBlkxRZZJiXxNp3cZiVxoX+sIM4eVCWQIAxenAExESpiR4Y+mRyzDrR2tsxn8 /5W9nMso8ZF7PQPXv0v9ETpvN1g+X8rw39Gt4w5/EGPqsSVHKrba3jn4a/bV+2uL/9ts2fkotu6 9MRMA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=heeo3ili;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Sphinx reports kernel-doc warning:

WARNING: ./net/bridge/br_private.h:267 struct member 'tunnel_hash' not described in 'net_bridge_vlan_group'

Fix it by describing @tunnel_hash member.

Fixes: efa5356b0d9753 ("bridge: per vlan dst_metadata netlink support")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 net/bridge/br_private.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/net/bridge/br_private.h b/net/bridge/br_private.h
index 7280c4e9305f36..bf441ac1c4d38a 100644
--- a/net/bridge/br_private.h
+++ b/net/bridge/br_private.h
@@ -247,6 +247,7 @@ struct net_bridge_vlan {
  * struct net_bridge_vlan_group
  *
  * @vlan_hash: VLAN entry rhashtable
+ * @tunnel_hash: tunnel rhashtable
  * @vlan_list: sorted VLAN entry list
  * @num_vlans: number of total VLAN entries
  * @pvid: PVID VLAN id
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-15-bagasdotme%40gmail.com.
