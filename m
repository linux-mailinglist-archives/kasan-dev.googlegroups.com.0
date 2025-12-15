Return-Path: <kasan-dev+bncBCJ455VFUALBB2HG77EQMGQE3BNZO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id AF550CBD887
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:22 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-34a8a7f90b6sf5849353a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798761; cv=pass;
        d=google.com; s=arc-20240605;
        b=iv4MPmPGnQ2X7CD0Gw2OQB65iVzpO7kXNxnYCPq5nJ2IzpaXyua7j0T+dLfmv7XKMG
         my4PeeqVI2Eq2+b+0uUpLC4kijCTz4OThnq65qtjQiGf2jIhSv+jAvJCmNaH1ZiPzeFE
         iZvFt2YxdBzubD09cVBlf051UlXvQPmxMVLaIhoGTx178m9bVNh89vVhcJMgZjRb0hfB
         mcS3rbg2tNVNj+VF1Ic7HGQpmu5pHIcBhuOg7J4+1P/Og536qBpmo9iIdQF1/VpGDa0K
         YJlra2uXaI2yZ7+Gieq6H1H4CNdQw5KNTwZPxmGYHdmiWI9gEGGckcWTenX6qWFZubhE
         5lKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=foH7GBaOe9IvTKBRo0cqJoPN6Tr+wIhkT0rwsI/F3Y8=;
        fh=my3OZ2Fpym61R3q8sdaOnvcnQFzR7lxU7ywvJ3NzpTA=;
        b=Rj8SiTZvx/U+sGcOBdb0qsah+C/uaSQ59JALNE0fyVuB9wZRBKcw8nDfLGX4HSp+i1
         nslkpMZQw0V9QpQffmlPne4SplEbeEBEBTXo3y5Dw+ROX+5V+kpoS1Scbfrfdn8i5kCF
         kNrti7ClPxW3AH/392hzAk+QwGEFSZMOmKk/Re3P6i7UjH6OwlJw5CRJewY3/QG568Gd
         BCPFXRSeB5CZcAUdBCMukasGxSjPBegkvioELW2WNrLtAp47ryCyiwApds27/ivm936p
         +EyjttZiruegZHEJPNJLQSXuQzpc4rH8SLM6zokMv37FuzOF3orxNO8h26V4bX2dGG1L
         Pl6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=f1pTXaz6;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798761; x=1766403561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=foH7GBaOe9IvTKBRo0cqJoPN6Tr+wIhkT0rwsI/F3Y8=;
        b=X2cXBCnEzfm0JqdEA2DUR5v6I+Ofmit/avHLIozfyFkjfc6aPdT+d/OM2wZlOK1ok0
         s9Mv4T/dmMnaq49x3aseXXMruMtI/qna3W77cRAYcSp8hEpgFJsyykZO8guUfxu4VOx/
         wzvjjwk4Vg5SXN5ugCAraPvv5r0+D6ihjuSUQYHUepTcergeNg8tDdZu46K06HiIfS53
         N0qkubNwmlM+j0Evh9X7m3WWtEjyITjNJZ0lQ6vGnVAAbxEcGQGBk9JwvYStWvhNV8bA
         0YsIJQ4i7yiHuRjH94etiNsZM0NKMbPxXwcBWNlJQ1YDUG7LkzctX7QarC60Zi1r8Tde
         nX2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798761; x=1766403561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=foH7GBaOe9IvTKBRo0cqJoPN6Tr+wIhkT0rwsI/F3Y8=;
        b=inAF1V50YgC1anmMGStjwLWzSQHaIHNWohl9ej3Zz3WRV3G8ZyIxfmkYdp7OlqXBai
         tBEVtW8KCUv04EHQSuN3yb1xAQVaOl5Cq3Whm5hgdA64F1VNXc7tWmUuti6f3EE+5EB8
         dQIcRqys4wBu2PZ4tXrDXl9Tz7Z95Gzg770DK4QUNkCYLo34G7bGD1v8Hde7mW46ISaq
         g10U/Vb0RKRpJYdR9Dl05wUR49fdgXbE4+FAXplANRO+bea0fZTIQ0iI7BUa1RzN9qHf
         eURQt1d/5f6TVIMQK0UpnrJAgUfQE5MTcDFnrzbJPf9HOFkgZznsqIT+em6s2+L8f1Kh
         PTHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798761; x=1766403561;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=foH7GBaOe9IvTKBRo0cqJoPN6Tr+wIhkT0rwsI/F3Y8=;
        b=ORzpOWdJ1RreRk3Tz5d3rnQS84pvVJRO2H4HFUQjgdQ5qxFzhhJmPpr1zOMDJVpwlD
         j8bF+vAiV1V2jcM3aEsU1NnxJv2krTtiEZ7I0hPw+VKQfWlPoq2635RHepgzOmmtwJBr
         TO1KSYJPmhLxlLUX/gu7dBm7nNwi55rNFKfDQS6/d7fBuRs4ZlQFMGDhP7vM50APgPZY
         EZm5Pewpz5tGNGQqq7gjP+N4SBxFU+wYYUbJXEhboog3AKoQCkoqw+D8xtYybaVGpM5L
         +ctk7Z6NfbsFMfGry+cFZVrnQotnRfksEfYErKBJIP1rUYidWedHtyfyVBU+I07kBHzE
         m2Mw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVEaYhavt6G3P/vT6CuhxLzaf6lm1LfspcsuclIDAXgtZCncYRgN9P9r3TWgnkdsU0TGrNawg==@lfdr.de
X-Gm-Message-State: AOJu0YxtX0fZ+juytqKzX7XZgXKDGurl2cMT9xT7G8HuZaeI0ucHj4FR
	iAXvMSR1XHoIxogf+vHZly1p+B9/zOnU/ukRbuwezKIfZ5wDNhWvSAs0
X-Google-Smtp-Source: AGHT+IGE4Konkm1Kd+56+UXulnzF1kaCqEMtkk/+lgwfeU/820P3+3dnh2R1yzmgLMrz1R2qhUsrWA==
X-Received: by 2002:a17:90b:510b:b0:341:8ae5:fde5 with SMTP id 98e67ed59e1d1-34abd76c6a7mr9809242a91.18.1765798761162;
        Mon, 15 Dec 2025 03:39:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbqRrRJJ45zYz2p0VkQf+jc6saPN6KnUO/219QtTI83ug=="
Received: by 2002:a17:90a:c912:b0:34a:8d2a:adf9 with SMTP id
 98e67ed59e1d1-34abcbc6420ls2744645a91.0.-pod-prod-03-us; Mon, 15 Dec 2025
 03:39:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU62XTl/Q+0I3k+WhvhCB5NXMNEV/iWumqUbuSXkCnccxaSUIMTtiGWVMoWPpiYKOHeIxfIwdX54IA=@googlegroups.com
X-Received: by 2002:a17:90b:1dc6:b0:32d:db5b:7636 with SMTP id 98e67ed59e1d1-34abd7853bcmr9305374a91.27.1765798759776;
        Mon, 15 Dec 2025 03:39:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798759; cv=none;
        d=google.com; s=arc-20240605;
        b=PIg/3l/C3F+FaPufoWxlOmRfdIglsXjwHmIlKA+S4OWqnsYD1F3zswFaQW/LfdL97L
         xOtxJFeNkjnkgOEd2Me3LiTXuMZEVZBp0Njf63Qmzi0i5CvOc6SnYyIaxGS8U8jurI1l
         Ui+qBaPCuyaFmtvMZyEyMJb6Nw7a8xcxO6Mt6Tcq2o2Cv553KKhhiF+zekcPV4Mvsri6
         V4WFPYoy9R2i5QOg+dDmIl3hPZT77WXbIWRWoKSJVS3vTHyBdBDKxgN1Z5iRYveAvdtK
         4OxJAo1XRyeuw0wI5usN7oSgubDhVZnKesjJTlPBgj4d/2VnP0n4TLngTfu0n2TTWU43
         7DXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c1jHunOtVkIwedmQvRsrzJgL7loZmMhygmTOE5iX6PY=;
        fh=UbA5+4u7ZMqD6kP+JnGgeSbypeB4ofe7dZpXNXaFkPQ=;
        b=W9X3K8hLWapMaPvKUoSES557+xvEXVZKh1kON7boa4R/kuGTQeEwj0phItIZp5WyIU
         vi8spICvWaTTE2Ymhv8yIsbFw4yt3lA5i1k1J6SwaNeBjNuZAsw9UJsTzrBRf9pT3lPL
         JIfjsmhTxPLVI0+DMhR4en84Y5He6Zfwym7PSHW7M7VgZtFjKo3M5j3XBcvBo6ppWxgI
         B6eBvybD7WyKpYIU9HzG/wCWvbcJfdUSUfWgncS54z7dkDHXz1/21GRAgjMlIuiU5T5w
         mBvuicamg2fZHwvANo3Ow2HlYhwd0O3o2VQLVniFCSIJ45evKY95R6B28qfOqxevNVtm
         Dwmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=f1pTXaz6;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34abe130c76si168139a91.0.2025.12.15.03.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:19 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-2a0c20ee83dso14693185ad.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUVq2S6wxh+sj4hlwqTVtAJ0LMdInMXLaDjgAGevLUW7Z7uXYFAP3/fAzUd/DxW38zPrFiFcQa92sQ=@googlegroups.com
X-Gm-Gg: AY/fxX4ii7lJIQCAXXfZlCnRKcStIm5Q9dURlK5jiT+YkNdYpR2SXsVnRMpuMgeUHF2
	E2KriRP8WriRZu9/H75iJW80iK+IG6giGaKDyKWzd0AFsQRz38oCSQrfGJNKH9YO8vaW1wpWTz+
	Y56SAvWIz48PmHPix/9w00yt4f1iwoJme7sgm+IKf3gpvyVLYgmtSfQqSzJotRXOYS/fsfrCEth
	EFZAnIvSpRYni56a6VAYVMxV5UobKRHXYGyshjddXbkuMCt0yR9vIrksypYAnMMWDy/JABvDGGq
	WQZh8g1nuf3lzWdCnBz88L5i73jEddBkdhIQMq6JbQXEEwi35d7s+wTAwGWrrK61/VfqcFmlu5I
	zboZ2xbXvqhP//+f84/dcZDEBs5FA4ni+5WScecUX5bl+hIMtv9XU9OhjmXnWBFWKL1KZvXm5yH
	XR2GFYhFJVtCe8l0cVOGqS/g==
X-Received: by 2002:a17:903:1aed:b0:295:745a:8016 with SMTP id d9443c01a7336-29f23b1e969mr90566815ad.11.1765798759332;
        Mon, 15 Dec 2025 03:39:19 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29eea016c6esm132730265ad.59.2025.12.15.03.39.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:18 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id DE7F144588D6; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 09/14] drm/amd/display: Don't use kernel-doc comment in dc_register_software_state struct
Date: Mon, 15 Dec 2025 18:38:57 +0700
Message-ID: <20251215113903.46555-10-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1238; i=bagasdotme@gmail.com; h=from:subject; bh=g0JdaQypaND4lTcW0ZqbYUYcFFa4BCtHp67rCXQ3qdI=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4OZ3cRMgut038Q1Mvx+WnR34qt26aRSjxQZU2vjg 6FirXs7SlkYxLgYZMUUWSYl8jWd3mUkcqF9rSPMHFYmkCEMXJwCMJFN+xkZVrl1e0394/7u+RLu +RrXLfO4ZDZ3GN7cIROa8FQ8sjv1CCPD78WiQS1yNZrTC6Ti9OZz7YjK/sxnP51XNFzRTCM96w0 nAA==
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=f1pTXaz6;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::634
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

WARNING: ./drivers/gpu/drm/amd/display/dc/dc.h:2796 This comment starts with '/**', but isn't a kernel-doc comment. Refer to Documentation/doc-guide/kernel-doc.rst
 * Software state variables used to program register fields across the display pipeline

Don't use kernel-doc comment syntax to fix it.

Fixes: b0ff344fe70cd2 ("drm/amd/display: Add interface to capture expected HW state from SW state")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 drivers/gpu/drm/amd/display/dc/dc.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/gpu/drm/amd/display/dc/dc.h b/drivers/gpu/drm/amd/display/dc/dc.h
index 29edfa51ea2cc0..0a9758a042586f 100644
--- a/drivers/gpu/drm/amd/display/dc/dc.h
+++ b/drivers/gpu/drm/amd/display/dc/dc.h
@@ -2793,7 +2793,7 @@ void dc_get_underflow_debug_data_for_otg(struct dc *dc, int primary_otg_inst, st
 
 void dc_get_power_feature_status(struct dc *dc, int primary_otg_inst, struct power_features *out_data);
 
-/**
+/*
  * Software state variables used to program register fields across the display pipeline
  */
 struct dc_register_software_state {
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-10-bagasdotme%40gmail.com.
