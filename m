Return-Path: <kasan-dev+bncBCJ455VFUALBB2HG77EQMGQE3BNZO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BD0A7CBD880
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:21 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-65b31ec93e7sf6405543eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798760; cv=pass;
        d=google.com; s=arc-20240605;
        b=M0EUwoTXQWwNhb/sNxLElUMcU/EazLfHH811IDeJS3Rpc1tDAeGXza366mMAmUue7w
         kXZhjQcFEdEJw1zRedarjbtPvKNfp4XrD/I4TqMvv1tBfD7OvHzv8PZgEyHd6GJSel13
         kfRDmQsPTmttBFtCYDi2bqnAczNVv0sQTXhNIHuHCm+qtKftHbshQCMFy77Opjhqfjer
         dNM1DdqSylvJCuqbYr4FoJ7/649jg4jzm4cCVdZnd5HnRpDtHDtBtn3+ENf9O5g/wjJ4
         m/LdyVpHfvENWitMWint2ALuuXBfOIGwHgNlQPqLcCofkNCMt5LZ7Ll+py85EIyiDRi3
         HABg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=LlymFt4mveL8QFETGRb8QR6m6xakgf4AQp7L7rNUB1M=;
        fh=mqbCFcwlcf9TiQd+LO8qWs7XrZKHZJ3Mzr4VQdbILns=;
        b=DhiHxI8Xz0gFyyaa2I6mL1cIfP4J7nBXUBnFm7PEaF7X/zYu28MNk2Osv6zWv2SQOS
         BH+q5pYH8v6cz4Z+wt/gRTkBNSBGNkj3pfEkYx8xgJ+I+DBF5eoxWgGp6xAEuOden0Tc
         O71hWWsMz0ssIsC2q+9uVuUcZThzX/qvzGpdnNWqM2gR0ykumKI8GR5J6HEgCdnZCNha
         KPPMfudT9UCYopCCewHobR4FMUmrM8iA2XHt1+kbxTIkcsDzHmixc+rlPKvaaMpEfgm3
         JQTlNFsiYM1MtuyR3+rsovnNV65RLZfpQBIQAoSc384GO5AQQQe9Mi+B9Zn0J8eI/tpf
         JYhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dCDtZ8Ql;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798760; x=1766403560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LlymFt4mveL8QFETGRb8QR6m6xakgf4AQp7L7rNUB1M=;
        b=gJXwJOiN5AEPdpeSSBvDVKzNzvlW/tSmjcSUcLrHUd9Dm0RMhUY37ajbsb2ADXJp0U
         2lycPJ+KIQEw5MewXoWGpEUuB3GnIjIdHW3eKAXwxSfawSbaImyoz+5Lkt7m4xKZeyV6
         D205L6H3KyuJm3uW76JuxqsB56PJjR5iqfJOgYwFob+6l33GM6KtwgisQuO/uf7j0yyc
         Q+PoNWDqoHNepOGegWvyJ60YPocj/cXJjQ+BaWXk2Qxi+0jqeocm0lEtPrEg5dOhhxnD
         p8B7sEkTjyw3kPPa7jyw7JP2n1voWSrlaMoufZkuWwusPiNcOZlcWLoRE0EIQzQIb2cl
         Azow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798760; x=1766403560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=LlymFt4mveL8QFETGRb8QR6m6xakgf4AQp7L7rNUB1M=;
        b=OALzeUlCM9YlStfiHbpAXf2+U21vU0pYh0SFHtoJqX2EvKS8JM89o96GQgHKyR+c6y
         jLe0ztLMInunrCeHwAW+uADgKDJkcDMwIuxRid41Xd4s3iH37IlEeHsluP8+GfMjPTB/
         kO7x5qujU7WCsIJ1amutkHMyvcDsAuwbv4v/K1RP5eQHAH0+rwRQa5CzZPV0UxkanQeB
         NhjfYpyHeX7Owrh6dld9WmxSnGUdRq/LI3Utkzsax0AWbc/evjE2MPK0lZXaDrdfc4pQ
         LXvL1xxuT2gpufrlvszDF9U5JzSsEkLHSgojqtotlmGK9qXdogkuoqXD5hDLaE+hG7Lu
         gjyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798760; x=1766403560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LlymFt4mveL8QFETGRb8QR6m6xakgf4AQp7L7rNUB1M=;
        b=BJ2834o03PLxR4ZpjaDci0ZsznIAX7pk6yvGMftUCDN83duyoZeMpdYTFbj90UR4m7
         Y1NLTSNjWaxGuwm9hbUmk7V2XaDjzYGL+EKTGfHwb8Q3/HiAkpNZvJN9yoQiihdFauId
         zXi9/P5FBrS/REwqWoCgkY8Guwe2iQ3hpiHe/kCPtUknCqTbShY6qA4A0HsinDau7vXy
         NgXHC9Riy5aRB6gG+azAl7uEwCo6CsuGjNVXpMyY01GeOUgaEPzFypik4Es912+dwdGj
         KNAMPKdBTGcH0WUAw9/yUQuFa9UITsZibIxr0wyRlyldrF+ckdrjF55Vg57jGWw9nplI
         GX3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIk/uLTSO01x0wN6cDnRyoA494sffhV6P/5qAnxSAqA6E+InusHGjfAQRsFdw1szVmjrC7Zw==@lfdr.de
X-Gm-Message-State: AOJu0YzfXw+6KhxaaaQIsISWfLGqRGOHGqjj+Zpe0LP3SvRegNm3AkZY
	cRcXHvSBs78sUb1vb7iQeaOKM9oW7FsyV6nHkvdPlh4zR/YxjikRV9yQ
X-Google-Smtp-Source: AGHT+IE1k/bzwW0PGcBSoAIqQBCORIs6q8dVwdx5pTsTw3ut4CMIOA7Cii0NbGr23sP2/mqbfJJLXA==
X-Received: by 2002:a05:6820:2005:b0:659:9a49:8f13 with SMTP id 006d021491bc7-65b4516d544mr4755761eaf.36.1765798760291;
        Mon, 15 Dec 2025 03:39:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZJoAIbCkcsqeqNPeyuhxguj+Sfs8IMLARWJpmfrdBhVQ=="
Received: by 2002:a4a:d189:0:b0:656:d601:dbcd with SMTP id 006d021491bc7-65b437f7627ls1154980eaf.0.-pod-prod-07-us;
 Mon, 15 Dec 2025 03:39:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX+RrqtlokyqWx1nk7GsE8D37ox/ttgxlEezUPTYOYTabGRE4qJz8Wv/gwh1XbtY80+FFVhk8T3Mn8=@googlegroups.com
X-Received: by 2002:a05:6830:411c:b0:7c6:e92f:41ca with SMTP id 46e09a7af769-7cae82cf1bcmr7103045a34.8.1765798759413;
        Mon, 15 Dec 2025 03:39:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798759; cv=none;
        d=google.com; s=arc-20240605;
        b=DOm2o59Vrn2zEkrHv5XfVC7QLs0344ycDSgiUtX3dyxkfRpe7nu+7gr35Q+cfpzMeO
         thUn+kVR2Gknf9DSEKb9nDwF/FzWTh0qdC9ZBpICDL8evj2EWAj6vSrfNPj2Nf0CZB0u
         HxR3nLxGrjGikwp0EVHZg2TXdtyDLjRcuHAtARgqlSiu0bNuiyIXTNSozMJG6BAPi+gI
         /dGH0pWjBu6ZCbAg8ULnU4fSEJ0mLQ9M2upYU5VVADalQJ22UBXTKPCmxSuL6A/ROVYD
         OSn/36ZnFPt2JwciZCVpSLnq/rmC9OBL7AChnStz2AcKR/3qSwZWAa5GgBrAfFQ+dNIz
         6MPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XhdWc9MI61x0CV5VCAtcSDjXy8TDKlNky9k0yGxBSF0=;
        fh=teAVNHtZ1VxCx+t5FVcxb5s+IRSIhKxCZdzfETa8u+Y=;
        b=SbIG84sm3G3T6qxq2+eqTX8bPCSciftFHw4PEttfpFYo1FhlEhZ1694xHLaV7/56jl
         2XxZk/x5CZIQLvhJ7S8almjD5IW99sBjbFByrSA7GJsylgK8FukE3ZmtHaNyyFe+axde
         O4PQu/jNNTFQ9CMkf7LqsxLH0gcVp2OyHcf+aYvo/KWj7NUQPnKONzJQm7CwKnuL8rCq
         TsjU1jeJJcOURWmGXurCvKvxAVpZNRtLz8B2kE3HesRtUwxD2VZxYHwtaybPfWLbrRqs
         43J0T8rh/tpNdHTOGuB8xySF0y9sXqXpF36KH+VqL6NnEljSpOyPjAi8H+jxm8RrPHuF
         FRNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dCDtZ8Ql;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cadb2aa90dsi566315a34.4.2025.12.15.03.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:19 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-7b9215e55e6so2341264b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUOEnQIqnQPiPkAoVswbUbIRsjssqjAAbcCbE3MrxXNqEg1nGEIILahorRq0RsxxoPzuEOREPegb5c=@googlegroups.com
X-Gm-Gg: AY/fxX4KbDIf5+yVupQcdivcrYePSzkBupRgl7SrBqP/W1yiJBjJS3lZW7xP0Sy3gVJ
	YLPsVbWWNu5zQGJJZghG39SBpX9e5PCUadj5Z9ckVbvsqu0aigEc+VDKvVKr7KCnX36MiKmP8XU
	HF7d33XMlhJrkMCERTO9d5BLev3Vqst/sGyIuSCb2lU6mppTgUDVzzKHfRtR74axyOWjWVcYZva
	d6ar0AcXiXbM2GMhhDT+u/b46pCZbMLKThmLR2fuB7XPfLy7K4t3B/bF2qHwkC3KMFLX1cAg2gs
	kY9gka+cA9EsCdXM8MHvMEJfpttVqDgp1TYEyTGUWKjcbgWkYSUnEMem2p3ho6m0Lz4BYbQNwae
	Uzpiprmz0xI2JpxKPcoruRvF262SyWs7D98r+6jZco6OG4WTgw7PVd2paXtjhovYvpVQJ4Y/DTh
	pdLv7PcaEaPFI=
X-Received: by 2002:a05:6a20:918f:b0:361:4fa2:9757 with SMTP id adf61e73a8af0-369afef5e17mr10497704637.55.1765798758466;
        Mon, 15 Dec 2025 03:39:18 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-c0c26eb1014sm12333506a12.15.2025.12.15.03.39.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id BCD48444B396; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 07/14] fs: Describe @isnew parameter in ilookup5_nowait()
Date: Mon, 15 Dec 2025 18:38:55 +0700
Message-ID: <20251215113903.46555-8-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=946; i=bagasdotme@gmail.com; h=from:subject; bh=ZF9oIk+6VfTU18bKiromuOjnT5V3QoMoKRjEOTmh6aM=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4NPZboGqi8J0lGIEPx09J91+O5zYvcmVc9uCnNeq KyqY9/YUcrCIMbFICumyDIpka/p9C4jkQvtax1h5rAygQxh4OIUgIloczEyXFE5FS25V7U4nF3s wsyajN23tv7S0jlgc8jW4LrtPJ7fvYwMd203HZvEp7U3/4W850Q53mn2BsnZf49w2jwWklnFefM GBwA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dCDtZ8Ql;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42f
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

WARNING: ./fs/inode.c:1607 function parameter 'isnew' not described in 'ilookup5_nowait'

Describe the parameter.

Fixes: a27628f4363435 ("fs: rework I_NEW handling to operate without fences")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 fs/inode.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/fs/inode.c b/fs/inode.c
index 521383223d8a45..2f4beda7bb8841 100644
--- a/fs/inode.c
+++ b/fs/inode.c
@@ -1593,6 +1593,7 @@ EXPORT_SYMBOL(igrab);
  * @hashval:	hash value (usually inode number) to search for
  * @test:	callback used for comparisons between inodes
  * @data:	opaque data pointer to pass to @test
+ * @isnew:	whether the inode is new or not
  *
  * Search for the inode specified by @hashval and @data in the inode cache.
  * If the inode is in the cache, the inode is returned with an incremented
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-8-bagasdotme%40gmail.com.
