Return-Path: <kasan-dev+bncBCJ455VFUALBBY7G77EQMGQE4EJT77A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E026CBD86D
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:17 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-34ac8137d45sf4132447a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798756; cv=pass;
        d=google.com; s=arc-20240605;
        b=c/z4C2OPJgujDemoJ/+3Ya94cMFvDkOOPScS7XhNa6kcX6EJDfTxl3F5CVA1B95jpl
         qjuAGtV2pvfgG/Zn0mgmMNY1jHM/n9alCfUU4ANGBivTCu3UTifKDy/w88XQ7VZQ2BWq
         oQf751tsSw5XsZfK95xyNymZhN1yaXboXqlgY6myoviHORAQbTnzew2Yp+q2bRvYNw3z
         AYk7W7yj0/50gfO8TRhhw/xBcOz3xAtGgkI9ZUvBK5opdZUCO5hg9v6cun+69vPZDAZR
         81VZImkiWAa99Ze3R7oQ+lGPxyao/DPGgD9ejq7GpvE+Ak/7hipx5aTNd3ZbyTEyUx16
         I7kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=oGapp3nT0LrmaUkxBW2RLEUR1eQm8aTGI5hXDPBl1MA=;
        fh=ASGmiTS/5wmBCwI/+Cq1CGEs5WvKEgbvtg8j6CJYfkw=;
        b=R5yLo47w26wYyazZUuYWDmtaSEns5voF/sJBVKl3/Mou8UoVT59NZPVJUMSuy2pA2q
         LhoZK8e0v8VX2e2wjQBDVIa0xzZ0hdU0RLNWWi4DivX0MfFX+GnF7K4flpjmTMGI+GxC
         dM1pff8o4ckdkehTFq8Gq1wRkdcLl22SV3bobUDdMTkYEjOyi+cQvK1cthNniuoLA5kd
         e4r1V3CQ2zN/5K1ypVlWMwVPZ3L0AFGREgAKJYjVMr20OkBph0Wl1XpmN/zcaD67FECd
         7rnhxqHM75Hrfi7kJDIfr9h//e3PPy/KCGfO4egKtegy6L61KuINgqiPC07IPy2ySINc
         puQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BcXgo1YM;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798756; x=1766403556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oGapp3nT0LrmaUkxBW2RLEUR1eQm8aTGI5hXDPBl1MA=;
        b=LG3donFMOSTjiZ6pFUsRSSVaQlNkSVpuPX1tA2X/OlVA3C2snOu5pGFMap/EAXmeGm
         sVSf5Et+SY6r/mlIKZF8Pp7wajqbZc8J0aK6jKt5iwEa/8oxl7Z4CsqCKr4b1WHg5eNl
         wXdyZ5+QVpR6nLSjwxeHZBn/iSWX6jTsah2TjrPztRVS9FqPr/H3Kl20NchQOuQFF3W+
         W53UCu4bi8kghmhtqKvlWnS+dOPkblP1sbvx6nsC1W6Dl6hQfp/4N2BDXsd9ZowqqATm
         06/wc3A+JBgMeiMd2nlA3E1PqiXktg/j9bGIjislVKrsOfj30y5TCLzn8Vzok2qE9Sew
         /vyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798756; x=1766403556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=oGapp3nT0LrmaUkxBW2RLEUR1eQm8aTGI5hXDPBl1MA=;
        b=PXwWVrnMEe+IGFtboZTm9TQRnY4iBxqEFnGpo82sSK5taAMVgY6cqM87+NbX8C1A5F
         0PnNcpIvnwZEP0gN/6csvXYfU0XkXGYXwwbUC6pTam6zd9nCfvojBv+m8tKoNhVtZdBz
         s5eHkTS1/8/O1P+tX5NpJOkpdLhLCLPgoWLPTKsMrTan7OuGrzDgMP2j12B9c0j9nNIT
         y7uAFdpCLG49/IyGcl8LRDePIWgOya4hjywqynulFqQ0H3BLUcUASRZvXTwOtMK0rmzY
         sLNKqVOYW/lMKc4Vt5kJYN6l7OO6OIqL5Jbpzm7phY1SWSWdxVxCK3KUV+SKYSs1RweZ
         gIkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798756; x=1766403556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oGapp3nT0LrmaUkxBW2RLEUR1eQm8aTGI5hXDPBl1MA=;
        b=FlFDSqDb/S6zUDFxMOvFySyspId8O6rihPeH3Hra9LKzj/rXNzZ9hlX2/ISeBjPGqj
         lHJjuAtGwOA+QQCk1v2O7ubuFXAaXjwZliqR9cv7O3DI+Z63povsPXrp1o/vn/gPv3A+
         TmgJsbBjnuy/u7mdWf58+TXVGoHOgjKdVe2+BXHrP0hxMrL0UAX5oIo5VXQ6tD4Q7lFw
         g7y6Se5V0ksyUBi1iyvIFTIWquvj+TJm1kjG/shEWBG4sor9pTnM+haq2AOj2R+AiKIZ
         fCLGebIJe8gU8jPw/xWFItA9MEmd4ALsH8w6XsqGyKFcRQvgik14n3guGSgUHHcC8yOi
         yeEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXW3GuIpoVeM0eqJ1bTRkB5Ui/0AKB7wMG7dfdUujLJeJX9NYPGmYgQh6fnSUWtf1dmYhmeJw==@lfdr.de
X-Gm-Message-State: AOJu0YyZYXe1inoXuViZN+jD0Qt8lqmFAy0N9rFc7hkaVXVeofvilzyM
	BsgykrQVSwpi92Z70Z7Fj+jSHjY8mqI5h5npTnXOccohj+zTlreXd1f7
X-Google-Smtp-Source: AGHT+IGoXzjpG9EKIRGlFCvrWWzIx6MostUQnRJ/qkUAniMTF+ssVfRt3weCV0E/hpDkKVwvZX3IFg==
X-Received: by 2002:a17:90b:510b:b0:349:8116:a2d8 with SMTP id 98e67ed59e1d1-34abd6c03eamr9704846a91.7.1765798755705;
        Mon, 15 Dec 2025 03:39:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZp9AmjEva/VEuwTUSaIjuaFaj+SVXeDzvBarW/JqM4VA=="
Received: by 2002:a17:90a:f413:b0:340:5090:ca5a with SMTP id
 98e67ed59e1d1-34abcc8300els2147320a91.1.-pod-prod-02-us; Mon, 15 Dec 2025
 03:39:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXj99WcNXz6PecSTNu88V+glrQz9lndzvgSSVDW6J9KQvDdPOzVb8MJhkAyTBAQihDcjphCzFHD70Y=@googlegroups.com
X-Received: by 2002:a17:90b:2fc8:b0:340:2a16:94be with SMTP id 98e67ed59e1d1-34abd6c031dmr9368985a91.4.1765798754356;
        Mon, 15 Dec 2025 03:39:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798754; cv=none;
        d=google.com; s=arc-20240605;
        b=Fa/wtLKLnnXXwk6XBke8Vomn+ogThDuPO9VxHP5iRa7hYMxF4NAFzEfuOCffbrIa59
         SRdipQGAcg1FdM0xZaWLJuBBBy4dMwvuJ2MKDPGNapZJxMIg5X2CJZjmIshHf1JfY4Hv
         qFTNU6PxeasPA95cgaXj6+uXiRADmjTIFtLH2jhN6ZkuqXdnM3XxX1oQqLxEOu6o9Y75
         VNR/2wQHJB8bqJTefZT73ep86QtEmPkx64GDFHcmOHxFFr1Os2O02QUNRI1PMqro7EC8
         dJa3end6q7R4loiw/Bi72si9XEW17Dtz1IVuhYnMXouNmyrzYhHv4otlUfVT6vDn0Hk0
         UAOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yYIA++CxPIcYPKgHl3oGianXtJJpe/hDcX33067gP64=;
        fh=Bn5xY3Qk8UAFXHMbcR0dCY0sJ1r7hAFwlDbp4zgIp6c=;
        b=ghqI3/CV/apbHfhKhVZ86Gmq7cIeOcmzBIKVW3tgRqDeuZN9adKJ1l02CFqXt4jEuL
         Otoe/yRgl1ylFjSUYDFKQ3RaS/ZvquDCuaywO/weYKtVZ5prnP3eAkxSJHG2wtSAgY19
         wMUWMkNv7JdUI4Yj3p+i1L4BOF88H67ekGx7SHdJG+A1fzIptsoNOxqrQLHZXoOOFKuy
         wVyY0xIazsH5DJNmhYvOCwR7HjllGjxFhOP6Zq5k9/+H1dJrKtEcyIRlUk7WDPItPcHy
         /0Y/dwI9uHe2UOZl0FaX4ImHXOjnENAHxqCbeUBuTR/03mxACc/JiMHU+UUwVm93zi4n
         7b2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BcXgo1YM;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34abe274af2si161554a91.2.2025.12.15.03.39.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:14 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7b7828bf7bcso3579518b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWrowMcDm13QibXSOpt9JR0VlmRBb71JDYt3esQb0gWCWA327wIy5PbfWErGEXHc47JbDS3ZNWDo44=@googlegroups.com
X-Gm-Gg: AY/fxX48dyJvGcbdOd0KE3khLGtghE/jZldQ3j5tKbuRq71ckZebEJqn55TK/RKkG6I
	7BAhmmYFyRWzvZ5igW8a6TWHCgHk3RgD6xYoyVDmr/b3vKOmUNBnOer1tpUGmkiqrNMeporOFGQ
	c9s92wGy8SyFDDfbA7JIOVQnd4OaNFxcUZhCqyRbeGoyhjEMIgH7QSuRoKrs9YluhFwYWvZljkJ
	Rsw+tTOaDRG2g3HYSRUfsGVAnq5/OsigIY8eD8VbmCvvIiT2AC3LKICjk+M+vDw9gxI+gmvnP1i
	kxP7gkx217vRGtMSSJT0ta2RhOr2cyaUAtqTU6SC/l5uxr9719pRtm6d6AEfZwHgETmDsULWtSy
	gBkl5PxVROE+gFZnSXJs+k02SaMwzrWjof67he55a+tRoqpyECTg9mlzz/pEZzZfX/eZn68qRf4
	8FbDxr8Wgme5o=
X-Received: by 2002:a05:6a00:4396:b0:7e8:4398:b36f with SMTP id d2e1a72fcca58-7f669c8b0e2mr9089763b3a.66.1765798753860;
        Mon, 15 Dec 2025 03:39:13 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7f4c2772cfbsm12557914b3a.16.2025.12.15.03.39.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 70D25444B393; Mon, 15 Dec 2025 18:39:05 +0700 (WIB)
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
Subject: [PATCH 04/14] mm: vmalloc: Fix up vrealloc_node_align() kernel-doc macro name
Date: Mon, 15 Dec 2025 18:38:52 +0700
Message-ID: <20251215113903.46555-5-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1025; i=bagasdotme@gmail.com; h=from:subject; bh=sT1prVB7LRNvf/W4XodTbc9bjm2B3700BxVWkrXUues=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4OyyibMaS/TcJdL00op76xZei7L2Pv7hFORU9uuV vT80n3YUcrCIMbFICumyDIpka/p9C4jkQvtax1h5rAygQxh4OIUgInIP2BkeHzeo3teoLm8pE9N cXOPl0J5QO7s9Yesjvev3nrjTaKBPiND/5K7Lkx+c2t1WS5sWq6V/2tGhSPf8dA5nnLdX2fcuhb OBwA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BcXgo1YM;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::431
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

WARNING: ./mm/vmalloc.c:4284 expecting prototype for vrealloc_node_align_noprof(). Prototype was for vrealloc_node_align() instead

Fix the macro name in vrealloc_node_align_noprof() kernel-doc comment.

Fixes: 4c5d3365882dbb ("mm/vmalloc: allow to set node and align in vrealloc")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 mm/vmalloc.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index ecbac900c35f9c..2c3db9fefeb7ab 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4248,7 +4248,7 @@ void *vzalloc_node_noprof(unsigned long size, int node)
 EXPORT_SYMBOL(vzalloc_node_noprof);
 
 /**
- * vrealloc_node_align_noprof - reallocate virtually contiguous memory; contents
+ * vrealloc_node_align - reallocate virtually contiguous memory; contents
  * remain unchanged
  * @p: object to reallocate memory for
  * @size: the size to reallocate
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-5-bagasdotme%40gmail.com.
