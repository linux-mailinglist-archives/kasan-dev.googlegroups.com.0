Return-Path: <kasan-dev+bncBCJ455VFUALBBZPG77EQMGQE5ND5F3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 76B76CBD875
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:19 +0100 (CET)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-6455731c6e0sf4418727d50.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798758; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q/r7ypOyJK+jaZs+gpK6iklwWpn19yrpQZY7HVfvYljQZAWCClbEmFz4oPYEl+fZgv
         4mx70DMAld9MXGaA/DzYjU+iJ9md8zlXwq0raVT7VRZVwBGsV7AVmB5y3dCTqEFTUMdp
         WI7SbVmPvA+NmgaeZJGReTyUTGbF6VC1xDtFHRDsdTG5WgDSwV+HmvfRVaKKnDoycQZ0
         QCLxXYplN9zywTztGYy4AJJx9zD3KKUh5tlTnAPlptjnUJAr0LsiMm7ML/ycR3s8t9M7
         a+DWk3jIrRWrKSCg9v4rLFXaMadM45Lp/3srkCtlqeAziiEoFjyOoCtkKs0DQmTmK1JR
         Eryw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=zYsN2Fq8PnPsnPjUhc8zEZ5JnUk0mW7F9R6UVWX6cHY=;
        fh=IdZnhIXK+ZuneN92SPom7dFOWcqi79ev6YBgxH3vPfY=;
        b=YWsKUNMbM5k3O6FNqR/Uowx7v3ctw7anDsSd1PMOuEoYGM9AxDiAgeEUG1JnWfL3gc
         XhRh0rx5TqFW0ra2SmNIoA8Xyb2+5qpkWtJm0o69dvNl6BFg+XTAMFWG1wCz3Fyag0mV
         /dVdSjUJeF8uKITZDurlsSueEk69+p0zF1JJIKMLleMUusHqbRvlXtgZXaUTvuzmTJSm
         kFSl/WJRA/sEj8q7L0v1F1nQFYCw3fV9AyiYOJvKvEaM/y5DlHeRvh/CbQdd6G7g78bI
         axdQnozs8iw3Dez4tq0Di1Ud4hM0ZfIUv37GFRp6K+mnzExMdzODdT0SdGRL4jvSdZXk
         18Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Nm6UAUuK;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798758; x=1766403558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zYsN2Fq8PnPsnPjUhc8zEZ5JnUk0mW7F9R6UVWX6cHY=;
        b=dSdeTFjyfIo8tdehAzDGdEBac8ghkFWx9KroN5K6xOMS7imQxEA6iMORHJ/uynq3b1
         Uc/c0v4mTblFC9uCDSsWsSbR6dOWj/cdOBv1M4zFQ3cXWBpHJC+nqD80oIbxVuwYnVKM
         8E7g9wUz4JKNIgURfZGCvmyppqpz/rKX3qXN8ZVuMqaT/wwEoOAKJlqzmO3FxvckMh9e
         Ao4aALfb/MHuMghcZfSLdo1UVSNtoxMNbaiODpu4XUwdFy4fpe5fgqTMvlVcunOCBIIa
         VzCI3fHfiqYjE4BemHIG6WuUdSTGsrkdqzq8RDZD9dyjNhdKMCMXs3o0sn0WZhi5gss0
         85AQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798758; x=1766403558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zYsN2Fq8PnPsnPjUhc8zEZ5JnUk0mW7F9R6UVWX6cHY=;
        b=jYFJxhyP02ckqv9HgIDQyEy/28qDDunrujzCNKDGTfIOBspBYJjGn6H/5OX4NxYD3U
         DfHWUT1DeMHex4qzWTtTNUAVHGLj9iKT7Pc7pNk5fVburnO+6tTuCGHSpJqXGVuTwDY0
         6jq0ks6wzVuMF8JXHgiU4QUlwsCi7HvUazSVLncYv+UxjeuUA4GfT/N72/vWsKWevq8u
         vGC4YihB6x8u4v2ppfqvgA6OJUZ5rMUYnCZqoyRj39JtoMaRKTt4VzhfkBEomtMS1dW7
         JcjNVxHzHqu3xZQG1T4DJI3/c41+9vUsSaicDAD8W1jONN33Wk9Y37HZ0jYsY0//xwdA
         FC1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798758; x=1766403558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zYsN2Fq8PnPsnPjUhc8zEZ5JnUk0mW7F9R6UVWX6cHY=;
        b=bJSth4oxfYUVy7uRr+8J7QDnvU4mOF8AzMYelvFmxrhWO6D13lSMVNoZvnRqPQvU0k
         PMvqRjDLchlgxHE683x3byP0RsqnvNtDoUpgEkxVSV9iYL/w3i2kJWmfqkGVzGfBcZgb
         H53iTsRQZfs7CPdCN/BmwWHYL84ty4P/ot3I/hDmxPnVs99R7Q/9Bg9bkynmavIKdIAm
         SXVRRXN0uKGZYAOMSTAfH3nhYwYlRB3fvjwEF/+825nxOL4RltkxrehSSER/CTcqzY8c
         12q3nAS9cE0KEVALbFUcZx3m6yJmOp2Dx3n1LV2tvPE9sE1QDQLZB7R0525LlVYocCko
         k/LA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXC9/FEIlg5JyzrMOQUPIBPYa7CuskS3Tov+54tzG+DwHHwvif3EtJEMGZAOCEMlDWzRkuv6A==@lfdr.de
X-Gm-Message-State: AOJu0Yw/ThSUq3LKV5AZeq0aWaF5LyYu4vPmW4ErNSbSfuEYyLYHx5Or
	liZEkC5qOAShuj5CBiQp4w+hvrnoJ3gbE+nEu+GipyLiZg7HKQQfNYXR
X-Google-Smtp-Source: AGHT+IELhkAcpfEMKH8pLBo24eRZiNv8ny6qiJKyjzThuwRAncS6rSfRMqLCx5gtDmbJ4XRL2ppRNw==
X-Received: by 2002:a05:690e:11c6:b0:63f:bb53:fe2f with SMTP id 956f58d0204a3-645555cdaa7mr8256213d50.3.1765798757966;
        Mon, 15 Dec 2025 03:39:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaIN8hwNcsZ7qAsEf9HfZI8gAIX+G8jThB2qX3byAdpqQ=="
Received: by 2002:a05:690e:204:b0:643:37ac:b891 with SMTP id
 956f58d0204a3-64554a30c57ls2107887d50.0.-pod-prod-06-us; Mon, 15 Dec 2025
 03:39:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWptNKxBgK4rUpoEva9U83RQwQQn5GcGe8pm1oRCAgOl3cnAF9u0mje7/RUY24/GTlTjZq+Q15tnf8=@googlegroups.com
X-Received: by 2002:a53:c7cf:0:b0:63f:9928:3f85 with SMTP id 956f58d0204a3-64555650dadmr8712175d50.62.1765798757205;
        Mon, 15 Dec 2025 03:39:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798757; cv=none;
        d=google.com; s=arc-20240605;
        b=g9FwtEnhfvIubC4ybKAL1Q8JYz2GZRZm/px31sNYpoMCcLq4dWPRsrgaAhAXgx/PGZ
         ldzGf8aHPPDkXCouxlSskkRbyg79GMzo7YqYDoiTd6Y1OoD6FY6q6ZOamdLKUpwlcHlx
         XB7iBZoa2FGW5Gy86nT5SB+U9Vf+0EOfPEmMXfK6R32zNPk5rqjBDVNALNFDtkSD+E1s
         rzReO34qQfR0aq00iWkvjGYamHBI/o508yYrN+ZNoeEtD78deIHwQJmKQYQus8ujhK51
         b7drx8BeI621ZPsEFvOXsWMseHa4Jlj/hq129iTaWigNSycJxrSfiyP131PQM3QTte+Z
         vBQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9thXFyBI9wECeAoZwvjVxFD8Ol9j6G4X/I1qZGpsX1M=;
        fh=Z1imiy0IFaTC87QqIoEjUKSBXJWRA/WwWiH+C2cFFTs=;
        b=dcou4XAEjoh9M69QJKH1oHWVCS9yFxjaROtW0Q80FP5OkJJNgUy5RPbP8yIU9kHMpT
         RmucfZ5ChEU1XXku2LQsdUlkOHkJ3RqakjAaMIt9baVlKcTChVeIj/BHD4vrcP6jLrqD
         4zf1ciQbkvnWkSO9lscnMb77O5ezGigACLRPGXVGciRyDYAvcs9u2fxqbEwyowDcYKjY
         QX1+wmL9ErWENukXNy3vWTM9yTeEQ7QdA9C2sJwTYfr/QveGK9OxuTJ6LYQWsCW+U4Wt
         wq4n1Mn7BGIuknTcKtS0h6JY0n+MJMVioKLd0n8O7orzmfd41u2xSymOZMwI4w/TNad1
         7xFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Nm6UAUuK;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78e7babd526si1456837b3.0.2025.12.15.03.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:17 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-34c1d98ba11so2665524a91.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUDJvdqsDH2gRVdWCWRdRh37jR+REqNUu8cS/Nm+eU2mhRU5UiqQVMD9ZOf/8dPH3EtmVSqjxKBvP4=@googlegroups.com
X-Gm-Gg: AY/fxX7c3CUze8FaJGU45x9ymsUVfITQThVp50HqxILJEvnytukJDb5lKUhgZ8x67Ji
	ucxm8ggHyvG+fRiCeuk+yCkLhuTZDD+oVPQIo/eC6m1iOJK6LD99f0q0iGhgbI86Hh9SCCwQUC4
	CxD0VvXtfNheb1up/qXjwIRhlKdvsvn/dVWD6+rUa6vWflLuqdyiEFzhXiO0z3JiRS5rUNsCj3m
	hfA4uJU37dZiSBRDljnfeAQWDeoMNPQn25RUtypiuZRQ6rGhdU5AfLD98miIQaG8pibfqPbJlFG
	EMWR/z9Flc7yUlPGRTddpQesjUPCp49gP4J1/wHqPO4qxpIJcUif/bEaDhdSciWLSipdc3hL8+N
	LpNt1RKN/rUFfa7UqX9JG2K/AcmSn87YpPDvhAMAJXdU3DiRtUVSRQ7W7/wuBj62Sv6bvAlajDM
	kqQ8DFQycZGYaX0M0YdGdarQ==
X-Received: by 2002:a17:90b:3d8f:b0:34c:2db6:578f with SMTP id 98e67ed59e1d1-34c2db659f6mr7063311a91.19.1765798756298;
        Mon, 15 Dec 2025 03:39:16 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-34c3f5bf65asm2652329a91.6.2025.12.15.03.39.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 9EFFF444B395; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 06/14] virtio: Describe @map and @vmap members in virtio_device struct
Date: Mon, 15 Dec 2025 18:38:54 +0700
Message-ID: <20251215113903.46555-7-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1385; i=bagasdotme@gmail.com; h=from:subject; bh=bVwk3E00Ao0/BsL4XlONNDCfpFF0qzpzGvJu4GqJ/kY=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4N3qByLSAtcbrWEYbHxfzPeVTVyK4Naco81fnbf9 sGw4M+ujlIWBjEuBlkxRZZJiXxNp3cZiVxoX+sIM4eVCWQIAxenAEwk4Ckjw37unJpIS7sDggaL LUJm/L7quGjlN51XE6JFNZoPynqvOsvIsMhqy5y4fbtebC8768S8lM/yytfC9QdFWExtD//Srpa 6yQYA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Nm6UAUuK;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c
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

Sphinx reports kernel-doc warnings:

WARNING: ./include/linux/virtio.h:181 struct member 'map' not described in 'virtio_device'
WARNING: ./include/linux/virtio.h:181 struct member 'vmap' not described in 'virtio_device'

Describe these members.

Fixes: bee8c7c24b7373 ("virtio: introduce map ops in virtio core")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 include/linux/virtio.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/virtio.h b/include/linux/virtio.h
index 132a474e59140a..68ead8fda9c921 100644
--- a/include/linux/virtio.h
+++ b/include/linux/virtio.h
@@ -150,11 +150,13 @@ struct virtio_admin_cmd {
  * @id: the device type identification (used to match it with a driver).
  * @config: the configuration ops for this device.
  * @vringh_config: configuration ops for host vrings.
+ * @map: configuration ops for device's mapping buffer
  * @vqs: the list of virtqueues for this device.
  * @features: the 64 lower features supported by both driver and device.
  * @features_array: the full features space supported by both driver and
  *		    device.
  * @priv: private pointer for the driver's use.
+ * @vmap: device virtual map
  * @debugfs_dir: debugfs directory entry.
  * @debugfs_filter_features: features to be filtered set by debugfs.
  */
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-7-bagasdotme%40gmail.com.
