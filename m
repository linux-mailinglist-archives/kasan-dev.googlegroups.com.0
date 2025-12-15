Return-Path: <kasan-dev+bncBCJ455VFUALBB27G77EQMGQEOL5XDPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id B8FF5CBD88E
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:24 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88a3356a310sf29471926d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798763; cv=pass;
        d=google.com; s=arc-20240605;
        b=U05hRVrNu0yJ+DJfE2Xjsz09bHWFSFUVxAEc8qGC9YeT//ChvYur2CApmhFwzdpjPy
         tgidrYZ9w0V6EaONNA2mynmnOQ584d+tu0EkQ9zG/GpvGOCeVrdkIDSWHTKZgbm6kXj4
         Xis5K5pSYv/yTZtCwrEgc7U5nLoJW7ZMkW+xV3j1GCBJzLAzWQeeIpsTv81ZChaFpOD9
         ND7XGQM1D4ZiqspJOAZtiUFgcfx5HeslOeFhkLha8mJg1TqUy0kaPvyTzo7WiHvpxyBl
         o2FglCt0eOkaAx3jf88IuqLYp57EBMHYeCFjMwRypkN0YSLHnVKO5vrr/OF7FXtJuLYt
         E+rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lg86cbvLvhxyQwVIz8LYHoMm1PPV58XGWeGsL2+F+/Y=;
        fh=ZOx1QnJUTEXPYWs+IizDjcHIb4kyyUeKDvenFN/awt8=;
        b=CcyvNwz24PXOZl1rkzBfjO/X0VPtM7Bi/GUvK0zu8KhR6iLg662D1MlswT38Hh0gcx
         H0fxVL3y1tSkrURV3jOzEzawA26d7Nz/tNMAdgjjVHEssELkvuIdYJRfwQ67cl4Agw6M
         X0jA4OYcqEC7FFcrkE4N11U+5u0TOTvI6yVnVf2CftIVdlhCZvV49SbUpzP9QlEiVNpW
         c5/Ad2wPkGtEeMtArHEEICg7gZTA54OF5H+ESAcDmR0ZJ3nDyLrLmTPLzLcmhXCOrRbW
         JWyYOky+1M25M2r7eUOdaDcRzfmYHFm0W27iz1GmdEakx/URnBu3OpNyC+CRh3E+5vhu
         zUZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Qz95wmmU;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798763; x=1766403563; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lg86cbvLvhxyQwVIz8LYHoMm1PPV58XGWeGsL2+F+/Y=;
        b=pjUED0b7Qi8wiMmmsYTy97WxEkbnfplV6zxR8Fhn31/qIxaXEFNlqbqcaGI0UmM6y+
         zMU+8DRSPVrgKZbx3vJId90A3IcjE9Vm2n/cPQGjvMIOOmfETc5PmBi+aX6M1zDVPFgY
         U+Cy1N4r2//yimpN9PkixI/+i4u7G/3IHthnsa2I1FHvDbfgc8NHJgFml02xcbt8kYk5
         izusBfL8K88NUACizYAniANo9bXxZnkfESbutBKve1sk98giIjPhqCNFnDGJliPSoIix
         /H62MOUuq1od0ndcqVwWDSi/vXCfP+p2JGnUZwP26lRV+s79//z6nVR+cPXXw+p03KfE
         PsMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798763; x=1766403563; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=lg86cbvLvhxyQwVIz8LYHoMm1PPV58XGWeGsL2+F+/Y=;
        b=YuMhuveSNl6YQ+9G8s+1CDBTVxkboGwijL5+ctH/fvCU9KjcBr1mbrXx2OoTqf2var
         zV9KzudchR30Z4jQQj0RJanXE6VnDGjcOOuiM9U9tFIuxaOLVP2sfsW3vkZIQNVsZzn1
         /LVNcBJSoaERxQTWC0IWIemBJ2knsNmo9ju1hrh2GCi6Om3fvE8F9XSmVOVNiJm/oe/5
         Q/ej2YcWnVkXyeM+/t/2Lvl/EGeUVM4+YCT4bHUd/HU6VuNpsbyt0FFFvznMKDhA6dOi
         V5x7RP7R1Q1K2VpvYqCmzlE/qjABVh6Fj/HepLFBVhVfQIiIgGEtHLXe3fmLjfTolCB1
         9qtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798763; x=1766403563;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lg86cbvLvhxyQwVIz8LYHoMm1PPV58XGWeGsL2+F+/Y=;
        b=TBsQXCW79/I23u9gje1KdLeIkvQvit9ApaM68wWYHlDNwysKZrFMEd7WkKzz1D4FNX
         wtZTQMyZmXKA5MZf50xE0qoDTt6adelpPe2Kbb68agBWzjNZ0SqifssrWc5h9UgMYL98
         MpJH8CVAizdWcqYc4VdmHUhmaTH2EGlQBnjLXlMOmwmjtiH6H2Apjf0IFAGQwpKCtaFq
         RuvKsChOi3Q4++1zZfhSiTfz3iPVhwHucbWQL3fyp9JDS/6fNUj9OoGbhBw4V9UaGhdX
         2wc/1VBBJCmvFVX5nKkHVvnaW0WGYnIAyt2+Q4UNgCryog9Hgc+dzL2N+AyzG1dtbTVM
         q9pw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURCNVwBnSJTnSrKDYhCr0Y5CTSFM7IM7MU6mFUu+m9TxgyE4E4pqa1zRkLW0FXPgL/B8ngFQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz3CMbisn12OHFPnxKhWb8+71boOc7+wfieHG5IhvIlnvFtJv3P
	WtDZRzN/FDUu6/xFvPoC72QuuuZDKpcG4qUzkemdOpUdnwgGvNQ1Orp2
X-Google-Smtp-Source: AGHT+IGcZCJPcpM4z85iYShXfPvCtcqdEHf0P7UP5DjRRjC+1xootrrQ3HTCfCJ0XUzxBQ+iGIDkDQ==
X-Received: by 2002:a05:6214:5008:b0:87f:bd05:1c89 with SMTP id 6a1803df08f44-8887e0fea37mr152645176d6.35.1765798763365;
        Mon, 15 Dec 2025 03:39:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWadCWWDF/cED0h3c1bgiwWjuPnuGH0xVBGddsHJhN1fEg=="
Received: by 2002:a05:6214:5299:b0:886:6a14:9437 with SMTP id
 6a1803df08f44-8887cd8b9adls51322456d6.2.-pod-prod-07-us; Mon, 15 Dec 2025
 03:39:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXoX45iNEaLAFNsSNTFOe4M9hRkXphYWsNTCNSLm3QZfYJfdYFMJRNm2RbGvTGGram3H6ui9C1b8ec=@googlegroups.com
X-Received: by 2002:a05:6122:1309:b0:55e:452f:7af0 with SMTP id 71dfb90a1353d-55fed5637c3mr3149105e0c.2.1765798762538;
        Mon, 15 Dec 2025 03:39:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798762; cv=none;
        d=google.com; s=arc-20240605;
        b=Yc16tkCZ3qiH1E3vuGSeXg0K5bjdzfhp29+9bBJF3sb7fBmswevMg3YNgf2t4k7UaE
         bygSaPEk0ynQFExzSrLQ2V1W6+rEHqS4lWK40u+0A/TM6xsQz6fpZwiAEuwUMJvsTk/V
         Dre6FVtQQAAZE1qarCkXcjNtUmyORI7eckL7gi6iw6mjwIEVc2GkqYvZSRBWSFEqcjrK
         R61ae2DVX5O0ZTbJM1009KPjXulM8g8VUq6vv6yq/h7XNMROcdpM/nGUnAWRy//K/KS4
         hajVv4lS1o6zZxH/MJyWaBFoxu2ooIf/3FK9inn9kROdYec9rrnAcTx3ndFrno9D8StN
         wJFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JUAs+7T6aM5YvKJFQXSXqoVkTtSxZtzq470O+YaXF94=;
        fh=5I8UvVcHcsrrCzpmEOjrhdjtFW74VS1+lwBuuufsyjo=;
        b=Ql3dGgAKgO5rOyQca+iHAkBEj42ts3Ykm/fOXvVRUedh3R+Zplpnz2NXaf0mN/cXAr
         ywGzdoFV181paiiT+YauZ9QcjNBj4lR5ZcQPJp4sOeC+Cxe2Jqnwu3kBDcXuieZxDqQz
         +CwkoVbVjj4Z1zYUWYAxDhd/EcFqEJTW90vTp/sFHdMbgw3c8Qh4R3Exrt+QnqT4KvaG
         Q5AuNaEv4m8QrIov4O2jlLQwxOYHhlT8pI0w2GCe6DunrZ9cZZLK7tkw0Ko+49yGtPzl
         Aet1UdxUZnmD0tu9tPaR69Z7+33RObvP+XMA60vHIhm45AspG51FWIRdJLe3n9T7zfof
         92MA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Qz95wmmU;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55fdc733b5fsi462225e0c.5.2025.12.15.03.39.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:22 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-2a1022dda33so6124945ad.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUn4ScysEEiwruW0YLo6vqtxr8Y8/tj7Qg4sIadFjl4kpaMmneIl/WcitsdKckwN7lddWERmmy9DLs=@googlegroups.com
X-Gm-Gg: AY/fxX7Cj40JVbRJvKqLeVXOCrPtelZqhb8JKOyYdh10cmb2aRzc7AwDdHH2SMvNRuB
	Deha4RM/AdN2F3KYwOgT8pq0i52nHxJeJkjoBIyoXJsYHN/emzl3lfPZ3JYT8pMnIHfHGsUgqar
	gN6B093JfVStNoKYCawVZ4J7bH0DOp94Y0ftXb0B7lF+mkaXxEPs3zjoRehwjdwYIzc/xOXXlDQ
	A5YpEGaSpImusbqg+h9rJpFcfL9KrnyN0VsJGtPRrUVP1K3SXmjPFurFDq9kWV+fgZXOtULdXGw
	ck7ggo5y/2NHFOafxuefMCUPilI3XJOJIEyDI9nBIMPoMGfwIx8uUJA11wDbU/KwVPMbiF0ziDA
	qPeNCm2uF8aOV9sPW8yO8834DM1j7cRUUDp/Y5wmWYbj4FVKWdFfebtdsEfLgg1T0wxxxc9TYQl
	pivfKfNmwHO/Q=
X-Received: by 2002:a17:902:ea0c:b0:2a0:f47c:cfc with SMTP id d9443c01a7336-2a0f47c0e76mr29563195ad.34.1765798761534;
        Mon, 15 Dec 2025 03:39:21 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29f1eff8481sm99000295ad.80.2025.12.15.03.39.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:18 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 46E2D447330A; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 12/14] drm/scheduler: Describe @result in drm_sched_job_done()
Date: Mon, 15 Dec 2025 18:39:00 +0700
Message-ID: <20251215113903.46555-13-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=982; i=bagasdotme@gmail.com; h=from:subject; bh=kdwYayfiPuGdbX+6/rKZkI1jkonQkDY24KG3T7ZKuZA=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4Pfzvv2aMJ6/2fiW3RmVPTpTFSM/fBW4Nu0ikdP3 J/+EMyq6ShlYRDjYpAVU2SZlMjXdHqXkciF9rWOMHNYmUCGMHBxCsBENP8y/FN2WnBW9dYhDc+y QzUe+4R7v/wRO/L/c0NDkJC4klf71CqG3yyrLnq/ur5px+nadXME75rW9sxVOp7eMOmL58xwZZ6 TlnwA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Qz95wmmU;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62c
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

WARNING: ./drivers/gpu/drm/scheduler/sched_main.c:367 function parameter 'result' not described in 'drm_sched_job_done'

Describe @result parameter to fix it.

Fixes: 539f9ee4b52a8b ("drm/scheduler: properly forward fence errors")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 drivers/gpu/drm/scheduler/sched_main.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/drivers/gpu/drm/scheduler/sched_main.c b/drivers/gpu/drm/scheduler/sched_main.c
index 1d4f1b822e7b76..4f844087fd48eb 100644
--- a/drivers/gpu/drm/scheduler/sched_main.c
+++ b/drivers/gpu/drm/scheduler/sched_main.c
@@ -361,6 +361,7 @@ static void drm_sched_run_free_queue(struct drm_gpu_scheduler *sched)
 /**
  * drm_sched_job_done - complete a job
  * @s_job: pointer to the job which is done
+ * @result: job result
  *
  * Finish the job's fence and resubmit the work items.
  */
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-13-bagasdotme%40gmail.com.
