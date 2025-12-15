Return-Path: <kasan-dev+bncBCJ455VFUALBBHPL77EQMGQESUVYOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A4EACBD984
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:48:47 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-8b19a112b75sf754097485a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:48:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765799326; cv=pass;
        d=google.com; s=arc-20240605;
        b=lNgtRj7Phck/xqeKAVzCXEWbCsx9O8Wffb9VUiqmYPrPjboNA9MV9uWEzhul56yD+7
         w0uESbE/4KUeSJaO/tzDRJWEbtWwrjv9JCmssti9z/tbA6vM0YrDx6FQfPAOiLdDdnXs
         lOxzzg244nI4bBBICNuq3awme3sQv0ZEcTURzcewat+HWFUY5sciFdXclioVzBNcs+JD
         s0MaqIcqxV8keYenZBvt52mjhMQI5kpG9XEPFpVD42ss2U5tteRT6JSs7kGqW6fVNzkA
         uA0C+LSfgft5rHXvXoT9AXYblQdp6XkTFiwSkC1LQKWokjtgVmuMYnoT1BnAdBqxvcZI
         JRcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=VHjabBJtTuvs5AyPuONFZOOFmi1hQehiX7zuDXaP6eU=;
        fh=h5LMuYe0b2wLVQRWxSc0AUqrMJDpVffwVWHT1B9KgjM=;
        b=Z1roc9PK02FScJZfZsW2mWh6LGuVtgbE6PT+eYd193tAgcfpjutiiXUj0caYLJ9F9+
         uPPFfuSJGCqQxupyi5Qu4d/rWfOR3KVtOV/CAiqKUNlTk/z84MwLssp7W/JO+LblPKGa
         a0zzVI+D3ihbY5VCZwdueVUzvshxZGxPS/GsIX5WkShQUj06TLTu8UaBq2lAytNPwGYe
         UFAENKkDS+SkGiF+zkqc54hqCCzUvQ3W2i2AtX6V+mfTSSOm+taJo1aTUkd8hhjmgiC2
         KXt4oRDPiLGiYiir7TAjwfQ69+7coGIk5CEXYvNJBFL4PTJzB1s6LhBfOCKwsk+qiAiD
         MTqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SeBHH9Md;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765799326; x=1766404126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VHjabBJtTuvs5AyPuONFZOOFmi1hQehiX7zuDXaP6eU=;
        b=X1RQexcvoBKNvdrKl85XCwulmTWsAz7FwIHz2ddnY6ad63L0L4qOyfd+6EEvd7+KfB
         pNs2s6pZN62dlHbWWVlWGXsPLrwS8DXrL9nO+BSZKTOxs4qQkHr6cryT9jwwUdKknL+I
         RVtfe7+oMRx+VK/zS7zMUu/t6f9F1S0FiUbgs+KVh3HALcYkUNDXFbol9vWYnIAcyqYb
         v8L8RMgm/Or324ZzPdzkfVDWE16gYVNO1HZqtZMnXbzjRSZSuZ1JLkZiOeX+dZaFlS8G
         oRCuLNZW3K/yBTw/7CXceHDCvi+q0nI+H9I4DQ4f6NipyKqWluEVNCWypn91JDObTwGX
         G+qg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765799326; x=1766404126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=VHjabBJtTuvs5AyPuONFZOOFmi1hQehiX7zuDXaP6eU=;
        b=H7YrGRvSHfRYBgtjsm7yshFySlTC5nbVnALB8CfSGt+rsmQZf8HPJzlPXm55saCJft
         kaXXRex2OYCd9jTpkzSB4Fd24n5x9jk1QpT7KLsF7P/+tmGEeHxJNMXLWmWypxnlwD1L
         MHFqV7lYE17j7eezZxjhfcVZ1PxXCH6i9a5qiUFnEZZrAnbF9z7sWMV63I3xvmITO1qu
         a1lJTVXg+bhg4zxjWtZyKirwsdiQW1XkvkAV83UOjXaLzOWABkfM2jvfJWygj8qZHYW1
         SqjWLGU4t75ZiQtDPHkDgCqwNZWTQeAWPO4gpKhVbAGYN2gfne+OXMwmzlsiOx6wRzjJ
         o3qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765799326; x=1766404126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VHjabBJtTuvs5AyPuONFZOOFmi1hQehiX7zuDXaP6eU=;
        b=bEZZIwUHQqiqpEjt9wK94tEpcL9BSIKq+sgHq3zIn7q3XIxX4VjrtoFws3y3XKpXsl
         VaIE3qnMf7rlD3NSRY8lPj/8/eV1uQhAAumssuXMEBV15xSf6crMekIVxC61hNX9lomE
         oyYeAICn3ptceKIIdYNaM679mYoJi5EKHof8I+bZSv5/f9dnjBGpWm/ci5L7LhbueEJv
         Ej6cz8lny6KhK/XwAr/GTlYvn7gc6tOQLPfWF1fgn/PxQuUNBkbKy8Sm2H5fZ6ZUiTSg
         baASB8c1YOQisXZ2s+r2T8JnHraEeKC+4TENG11NGcYb0iMpzPEIklDe1WiScfNWcfKK
         R+YA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgK9vF9iYvD5PaAIA6PsjXmBn4Sn0I+PYa6ULHcVR0i1xsYh9vygQw0DRlw68SMrblRZFGrg==@lfdr.de
X-Gm-Message-State: AOJu0YyCJ1YFJCfD/bPTHa89L3KK3MGomeo6FPj99nR8kuYC0yxF8rdv
	mtLkPfR/iPXC7wT5L0ygFXysgj9SN0x3ts5DNWstcptOBBma6AJUQM8K
X-Google-Smtp-Source: AGHT+IG+MzJudMYAqRmiBqfaw5uQmVOpuzHRmg4+dVjJNd53kQPRbbM40ZqRDryY7z1jSwU0Bdky3Q==
X-Received: by 2002:a05:620a:2011:b0:8b2:7290:27f6 with SMTP id af79cd13be357-8bb3a3889d4mr1118029585a.67.1765799325963;
        Mon, 15 Dec 2025 03:48:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa5EDYcQIYbZXtqwBjrBCnGYxm1zMXLrygJ5JSnuX+sfA=="
Received: by 2002:a05:6214:e6a:b0:880:59ee:ba5 with SMTP id
 6a1803df08f44-8887cdc4713ls66003636d6.1.-pod-prod-02-us; Mon, 15 Dec 2025
 03:48:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU2hPbBGplSJC6hGDK4sYiVxPle0XiIwZsx3WX4KiodupXa5FcKH4+gqnh88nS4cHBSfS4FvJU+YVY=@googlegroups.com
X-Received: by 2002:a05:6102:54a2:b0:5dd:c568:d30d with SMTP id ada2fe7eead31-5e82783585dmr3575706137.30.1765799325009;
        Mon, 15 Dec 2025 03:48:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765799325; cv=none;
        d=google.com; s=arc-20240605;
        b=W8KzgGTFAUtiskj67XcB7KT+2QqHXu18YHG4NPJss+Au46+7QeEQbo27WbVS2ITm7e
         OsYTVctMg1HyUQH8M7eLmsmMp+sJnX8SmAoKyHoDtmlvUhtBFDyqG66676aBKUYIU/GS
         NwIt5VI9V2sk9nkfrA3Er9CU4aVwXUt0UAvlbvG9MQzd16g74EtJ9r+eSKELVNY5IxaL
         avclvNLD87HBQYxnWEEXkhzBnUI2Ws8k1hazb257vUTN3l3hrNTQNYIRpttFhQBahpcV
         VBkSTGu60KUb9RnTNxj57SGMqMRzl4UIF9Z0NnMGcdSCu7L/ejg2puuSEiY6+asjgPVN
         8zdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6HauKBmXABfepG7VVzo5pWgXSZcUBePm/ZvLfsSGC9U=;
        fh=Rk2Zbkhw4bwrWXGle9jstyakGCe854nJhgs+ENWGFuU=;
        b=PCZeR5a+qTbutpZwsI8qff7hojsgVlPl+A8FS9SZSFQQRDwyItJOaB57Yx+Qy08xC3
         8FZTAN7iixhGBKQPjOSZKcNl4K8N9lLextr6PLB/0mG4t/41s85m+xemcG6+Hn5s3coy
         suLGvNffz2Iq6cfLGBGTlpFYSJBCrKMf2AQFviuQmKrzOJUD4FgVI7zXp0MprEaH9njL
         t9yTNw/HRE/hMvhp/PqwJWuE3kJl0A9bL9AZKjSfI3tfSajSnrgGepjzRll2cz4OvkpK
         yKuCBUDqMPMu8I4o6eD+PQH+85MbUBtuSut/3MrDJVmjz8Sujz/hpYvOz1zCfBfDN4eV
         ll3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SeBHH9Md;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5e7db216f53si218706137.3.2025.12.15.03.48.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:48:44 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-2a0d52768ccso12881085ad.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:48:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXp9Op81hVuHJPllX0k8ROxpsAaGFv1XAU11B2Wj0Kvvkgi6LuG5k6OK06yq8XXxkNAqISU8uGOE0Q=@googlegroups.com
X-Gm-Gg: AY/fxX4oyJ7vSTHlH7tU4EI/PSY9PoTGJXgZgnKnaKAz3Gak7crO82U3qyZ16ecmwfk
	c7mygld1USqA3c/FNYHgU7zlOpYARRrzln5dNB1HoTv9I6uE9Z2Mi/uJAe7QntJl5I0vOuAkAJ8
	Oci6Zebl7ZPqM8sU8rksB3iWS86YQ9W974PvPqbJUKs5OVumigDt/OqgdK2LmsS0Rr0EK9tL0Y3
	o97An+a0jpjfPAjTn3itPmxWU5KfxuW2De4K1I3AdCoRxaMzsLWJ0b0m5TJvwQDkE7aF7uKm5p4
	Ld0rT0Hz6Lu+YCHSh6Ybmtg9hXKx8E0dQi3AsrdLcFKYmbGdzm0Lzx360+3BcJAxoZSSEkUVJod
	/mfQ3e19sYTdVwAKViS4JPhIkJSWTqc+e7ecW6lzaO1GTtkKhy7uuAk5swHJs8lKVIsh6bU/Rxa
	wJDLWzs+UCYywFtfuZuSfdAA==
X-Received: by 2002:a17:903:19e4:b0:2a0:ccb9:2f0a with SMTP id d9443c01a7336-2a0ccb93179mr42859105ad.8.1765799324447;
        Mon, 15 Dec 2025 03:48:44 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29f271bc8a0sm97458485ad.92.2025.12.15.03.48.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:48:42 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 1E64B44588D7; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 10/14] drm/amdgpu: Describe @AMD_IP_BLOCK_TYPE_RAS in amd_ip_block_type enum
Date: Mon, 15 Dec 2025 18:38:58 +0700
Message-ID: <20251215113903.46555-11-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1065; i=bagasdotme@gmail.com; h=from:subject; bh=UEs/C9BYSnit6YUYNsXI/TPVZ8wlbVWtOoMfZCt2Czk=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4P/rZd71fJeeea2Y6ze7l+/BUWfvZxbPVvJ7FLhc b8Ca2nfjlIWBjEuBlkxRZZJiXxNp3cZiVxoX+sIM4eVCWQIAxenAEzkQCXDH065v1Nu7J+SJNXm fKBEpbzzpEZrbklCWe8WSUFLrulTkhn+J33s75ffwvJ3fu98iUql0+pnUqJKXmg5a8ursxTsZFv IBQA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SeBHH9Md;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636
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

WARNING: ./drivers/gpu/drm/amd/include/amd_shared.h:113 Enum value 'AMD_IP_BLOCK_TYPE_RAS' not described in enum 'amd_ip_block_type'

Describe the value to fix it.

Fixes: 7169e706c82d7b ("drm/amdgpu: Add ras module ip block to amdgpu discovery")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 drivers/gpu/drm/amd/include/amd_shared.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/drivers/gpu/drm/amd/include/amd_shared.h b/drivers/gpu/drm/amd/include/amd_shared.h
index 17945094a13834..d8ed3799649172 100644
--- a/drivers/gpu/drm/amd/include/amd_shared.h
+++ b/drivers/gpu/drm/amd/include/amd_shared.h
@@ -89,6 +89,7 @@ enum amd_apu_flags {
 * @AMD_IP_BLOCK_TYPE_VPE: Video Processing Engine
 * @AMD_IP_BLOCK_TYPE_UMSCH_MM: User Mode Scheduler for Multimedia
 * @AMD_IP_BLOCK_TYPE_ISP: Image Signal Processor
+* @AMD_IP_BLOCK_TYPE_RAS: RAS
 * @AMD_IP_BLOCK_TYPE_NUM: Total number of IP block types
 */
 enum amd_ip_block_type {
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-11-bagasdotme%40gmail.com.
