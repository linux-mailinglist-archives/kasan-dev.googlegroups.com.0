Return-Path: <kasan-dev+bncBCJ455VFUALBBYXG77EQMGQE53NIEYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CBFCCBD866
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:16 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-7c6d3685fadsf3650090a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798754; cv=pass;
        d=google.com; s=arc-20240605;
        b=fk1Bc2IWQCNWvJr3MZIzc338IheUzuUFna3FN6v2OjF559Y3hBQ6bZ3djwCvasRx0e
         Q8xhy1KMDGBUXqcBhzaojiHdUyprMbzhMk0GrUJttrYi0ynyiWl7qafF25Wyqv9vqEXQ
         QDMFaZ3svUUafeo2/EFmNNk1pRPeBG+cE9DIVQWoKQJejiDcw4a1uCzrYGrCjDA45Ivx
         EIs7vg7VGHlbk9wQJWq/gpAfdW50i3lOXWEJE71q2dNnlJEFEA01WXHEwFYRMxZ7AuWf
         kLOQZnWuwXUti48K7GEmZR6+p9pTp+IYqXJ0zxnlhkGBaXA8Rb3DDJkOG8h3KlG8JuaZ
         nhrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=kuuLRGFQge2SYGRJIheIGipy8O6x4poWPak8DlMRCk4=;
        fh=m8ijl0oHrAqIiydn98RG5nBBrp2/SzsHlxjDhX0rJ0Q=;
        b=jTlFB2Ho4Z16ZEoU9nRJPSnyPQBDw4FPRzNqcEbwV41619e7JTHIOi7GcRnzFCFACa
         DtP+8k5yLlR59+XrMoMFvfivuvZThYpEVuU8BB63c9vcXIByIQ6v1u9qnxibuaZvGUM6
         QxeZQEzPUDhqSROszES9ZaAjbXch6fCOngyToOIjJ0LpUDr6g5Diro2kIm9m3z85aDn9
         W6c6+bsF9yIgk2J/we23oOJ/XFHhRnZZgXQRWKSQtH032a15n+XCL9DyoSgNJVEpXbJ3
         YNuHxJTNXdog1yq9KJH0xAQYC4s7xIxu/3t8mWG1O+rIDfj1Yxcfy++fa9MVy22JRNtS
         GW1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UwbbSdvK;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798754; x=1766403554; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kuuLRGFQge2SYGRJIheIGipy8O6x4poWPak8DlMRCk4=;
        b=Mq6VA8KnITq769GhCQmcioPksQUGerFEAteySfS0C0wpMxUM8KmDr3nLhrmN9m5OfW
         fnoXgzrcyo6G+mh/9eyig2eJvHnFQ7VVaXwkTWD1Rh9uAJQJNcDkNxMCw/ODzoQlx1oR
         7XyB/eQ3NhXjymqnfDar99ZZFaS/L+RwTb3tSQl4EREmv+nMZ6wcc2wIUBcCT5u2rAKM
         74NfcX2ZbGpXvOq+jbv7SvnmWwSwHQsMI/brvLl4P4JDi6X2kaDXKLp2xyHtZsNReQRk
         ThsG3c2j88DDPkmrhx3+yqss+kxbcYM9GIk3lAFL61qZ3hHRanGIJLv6LuGj3ldxrjrz
         gbEA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798754; x=1766403554; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=kuuLRGFQge2SYGRJIheIGipy8O6x4poWPak8DlMRCk4=;
        b=YRlInkhnEiC4QN7onsSr4z07bJN7f7Iqe2tVcaq7ed/DLn4GsHGfrsDXIVw/ymNWDl
         sMq5wa/P7osDeFj5VVfPuKYukb+bMtYreBv42Dx+e0PlUnKHS7VBMwM+uJW+m6BMLEaC
         b8FQrm7cEUZEHSpqWRDOJJcrFo8qiCFBfDfCoye71kb6fg+Iin2fJky29HckXWd2dD1d
         ADWdjQnmR5GbH22R+VTetENR9gKgFiJyNEdSdGT+1JU/+C7FWA4Xk83fxVsIIkkTzPCL
         Bad5cIE8iDg+0xKKzOexrOCIGXhseIoktXnT6GpmyE5AXHOUFawVT060unSWw+4xV5V6
         /dpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798754; x=1766403554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kuuLRGFQge2SYGRJIheIGipy8O6x4poWPak8DlMRCk4=;
        b=NgLVwVAZ2gxXi+K1hlUi7l+C4e86kQHVbcKq2zmKS/o4hRO6wfzoPneVdnIcGlTBEd
         wjhI+tzBDi1KxREs7X62X3T0g+XuuNiSSuxy1mFSY6zJ78O7JbfMo9bhd4LvNm9+UQwY
         rEb/MDVQL0qCaHrjpmNxfY4cW6wHnqOWAQ94IIU3UEGakY81j1Izade8ZUrxAv+uDbj3
         plDlrFaHFu/IqG2h3dTrtrb+66HqHvdb/evkOYNgA4hPppWcACoh5MhZwxDCzE41BoPD
         p1fmsYzH8y7a7ggWgCH+Ta2R+wnbdKVD12l/cunXHMDQmZoCZVpYHzyZBIF7ga3rh6wo
         4muQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU9qkOERP4OVv5yO6hhmGN+9KQP/Te9cYdF1Dndx/fea5nEPa0N40VN2/wmdVx1aeuVKM/3Ow==@lfdr.de
X-Gm-Message-State: AOJu0YxZwJSfy2db1xMzumS0uFr0V0wxU44JBoutmnppgzed13J2pzoP
	KnLxEgdQOoK68UrPbdpEhsPOhRJGZ4w80pvcYMpQ1yWVyXlRksN9L/4s
X-Google-Smtp-Source: AGHT+IGc6gqQ89g2r/MWR+6l1cZtOyzu4cwNihut8vJASJ0WG4DAwAU+5L6xuoz7SAvcWVkoxPAddA==
X-Received: by 2002:a05:6820:4b98:b0:659:9a49:90b9 with SMTP id 006d021491bc7-65b451e3cccmr4656149eaf.56.1765798754330;
        Mon, 15 Dec 2025 03:39:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbR1hqdtUCxQjxgnoMB0KB2hSUq47vn/InrDokKaslnKg=="
Received: by 2002:a05:6871:2d6:10b0:3c9:732d:60f2 with SMTP id
 586e51a60fabf-3f5f87a0991ls1003114fac.1.-pod-prod-02-us; Mon, 15 Dec 2025
 03:39:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUeMrBBUDnDYu0svXq/Cmrd/qJUXfnXhxl/qhK/WNdKN3gPA5LPtr74oqrXdBjd+u9EbQ3XWyrBOfc=@googlegroups.com
X-Received: by 2002:a05:6808:1039:b0:455:db06:33cf with SMTP id 5614622812f47-455db063547mr252275b6e.2.1765798753585;
        Mon, 15 Dec 2025 03:39:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798753; cv=none;
        d=google.com; s=arc-20240605;
        b=QK5b/Maz/iHwoXASh9436dn13Gw6s6xgXcj+RDoN7P6Tbr2YzzAqVjkv4Ha8bpQ5/w
         qDsgKKgxjuzc4r6he5zHR8P4Ce4/45KrnnusKMic9LsjmctDzYx18ElEWVt+wXr7nwWq
         949XOQenr4QYTXOElkfNEaxn25BVsm+fuWGr7PmQIdiIPDBASLFLOrm/JFHfuclh7kV3
         EuXzqf3jFElTD9IbtQREjue/U2T/ik8qg2ycGpk4OsHw50Y/qcYZVwYstUkGn/cKMecK
         jx5mQ2mnDfFof+N/1gdnB12OCVSvI+nXOaUlvARzrNxqjVZrMOuXBHzwzkOXJS51L/3H
         +31g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lORwJoeOdmqWvp6Gaq9g1tKkad6KEP5mAC3mejLEu6E=;
        fh=gUeSTkhPd61jQxjEOC3+wJDQN9AMVjm3O1JPekKQ+40=;
        b=LvMIfVwyVQCO9DRt6Xqlb0inhZeirjaqaa3kScZlclB6kk2BKBlfnk2Y5FH70HXcvm
         rr8uRE+Qp0c9n/IPJFKow85+bH3RqaKLsuVVHugCYwxgyn6jy1Uvh3qiEw1FadCz0/63
         xr3c1kKFqNdiyOQKb+SFlPheFBkSzITz1BN0tG74OFL0TbJDGQW6T7xJPhLviASE/+qr
         LktNA3kjgMpuUeMSY7rgGFo+/gpHEfIEbo6UzVyzF8mVgL7WRNJoEnBa3jiXKvbaTesB
         kUkz4rGd76JjFNwIZD78cgw4++7VvCE1VFkoaFrgtaKbc7kpCZfBggzr/HIAqGsMkCfa
         bOYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UwbbSdvK;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4559894fcb4si290902b6e.0.2025.12.15.03.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-29844c68068so41021725ad.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVwKnscBHTgQn7lCCHE+uMFWiHJ4WEU3L39YCK8CMK/xF7VI94nSGQMjmHIWDL1Rx/KI+s452X9xiU=@googlegroups.com
X-Gm-Gg: AY/fxX6dBCH6JU7347N35Q3+2f3VZfIz1gzzDoeXZMfN/I4w12iUYJXkTyxOz3Y13kU
	2eUNPAL8zcdd3c7pnjqFZkmez/m1e0pJtRqvsnH3iv1w78VAVwWDNMxF117Z96Ip7bpb87ABoaE
	RFaZ40mBJWkLDGcIG3WL5pgR+3u4YtTXnv7mT6KMfYTInOerGvDYVhgWYwInsoT0h5m0Mdr4aaE
	E4HAwGBLEbtK/nZYRA7q+UnVnllfLT6aIeV1Gcr9zqDNRrvJR/GTjRCr77NJRkLeVWJLAKLTk0O
	hwcl5T7TEk9CvIx6OdzntpYZ7m2ipO6M+pf7Uhm583TXcveUBNfCCjiBGzupYLdG16N58K5TwQT
	dUNQCl1mC9VOrk5TWHwTTBxdq430h3/S/O3N6FGCfJkPJMJX/6HaX850WUxZ90KHVjAVGr9fFwC
	DHICkRo69iaEI=
X-Received: by 2002:a17:902:ce11:b0:2a0:c5b6:67de with SMTP id d9443c01a7336-2a0c5b66910mr49896795ad.52.1765798752888;
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a0e96df1c9sm32031235ad.39.2025.12.15.03.39.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:12 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id 811FA444B394; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 05/14] mm, kfence: Describe @slab parameter in __kfence_obj_info()
Date: Mon, 15 Dec 2025 18:38:53 +0700
Message-ID: <20251215113903.46555-6-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=849; i=bagasdotme@gmail.com; h=from:subject; bh=mcnZ1soLgF/JTT1YuxC/XOQhVy9SZYDoshinxHejwDU=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4P0Tdf6vI2dt8iwUrrPLU6ToytxCmtRXso3wY/50 fGG9Ws6SlkYxLgYZMUUWSYl8jWd3mUkcqF9rSPMHFYmkCEMXJwCMBHZKwz/nVbIB4ee2zunpOHQ vBz35Ga7xwYL3V6/ES+tt/jmsMTsOCPDXNsiGd24sMjVrB9Z5rD2NZvPm8/+bp/rS8/i2IdH8rc yAgA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UwbbSdvK;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630
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

WARNING: ./include/linux/kfence.h:220 function parameter 'slab' not described in '__kfence_obj_info'

Fix it by describing @slab parameter.

Fixes: 2dfe63e61cc31e ("mm, kfence: support kmem_dump_obj() for KFENCE objects")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 include/linux/kfence.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 0ad1ddbb8b996a..e5822f6e7f2794 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -211,6 +211,7 @@ struct kmem_obj_info;
  * __kfence_obj_info() - fill kmem_obj_info struct
  * @kpp: kmem_obj_info to be filled
  * @object: the object
+ * @slab: the slab
  *
  * Return:
  * * false - not a KFENCE object
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-6-bagasdotme%40gmail.com.
