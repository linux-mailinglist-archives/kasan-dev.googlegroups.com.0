Return-Path: <kasan-dev+bncBCJ455VFUALBB27G77EQMGQEOL5XDPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 782ECCBD896
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:25 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-88a360b8086sf22871106d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798764; cv=pass;
        d=google.com; s=arc-20240605;
        b=bTJAfVq/wUU4v/ZbP/QOkHkPSLyoGYV33fDeEmxWWboK/0zZhXxhqrTuYU+WDxQSON
         QOY3G/7YMXj+LVTFJIvfqXc9zhHIillEP5V8XQuh3x15AxwIaMGYnbyNBhC6sPmVicQU
         tH0YZelCQ1FN21EFYQx+3lhGpYeYhVx98Z2DBr8Su/VXhRO4vjyw8VaTyf3tivp4qKPC
         I0E2kZHlcjxtPq+1ptowypjkkKJgEcWR1Kl4x9b5q7UHtKOxtorZi7jnq6gxN6bpkc03
         yKTYI6VGzTbXl+4BmDbqfS4C1PXR4bYHah5syclq4ALYcA8fXxsdNFzJsHcu6qQEEqfI
         lqSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=b8b6VMtEEckrp9RjkOUSf5evGJUMqu+qh25lAgt5us4=;
        fh=2qL48QGRrzmMn5fBzo+y5BXLQ9KuuwG82/s59cnAzok=;
        b=cxwLGRnsdoMryP0IeRU73DrcjZHXtiJeD+BEN78NQe+FL9+q577EG4kFsEWd3TDlO8
         Sx/dngqIvGttx/qQOMPRo0MCpwaZ/USwS9uhf9H71JT8uTe7OIa9UZjPgHNSq7SQCe2V
         9U4qp7zdboxu0aXl7e/jsDkd9GGNolnugdzdZpmbgQBdGWPXxjedBCWcMVKdt9srTZOR
         TBVpr9ES9FDtNGhYmyKJfwtrMRPaxF3h+C34Ec54ayZpQL7SJ17EHROYrvjL2c2uH8ry
         FUJkPT0r7pMvRgYJ5UbfjVpDrrBp/d6WRH2ezRGxPqtNqwzQVGNlmASuAogf0uILRa2w
         o+4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SfMeWQWi;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798764; x=1766403564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b8b6VMtEEckrp9RjkOUSf5evGJUMqu+qh25lAgt5us4=;
        b=Eya1lTwxUIrQ+N3MH+rktLOE9Z3YJnY9QaNlMWJpSCIhGHo4pMNnFgGS28Bq8k+Bgq
         EqPaeAtwgaONMO+b9GbDmq2l0J95Qf0vaMX7UFPbYg18q8ZNLfm0mGapDOb4Gr+JSnCt
         GAMVVqy8lMKgNarOv0JVCuJej+0/+kRln6LcRylyTrU2swHZpimoilDLmjZMggxs9Klx
         IBm11FYPM2pmpkI+nv0TH1WehDPM49XL90pD+dH+QgQ9cEEuOfDViDqzR5JTWR7tgB3d
         LnGpiFmpO3y4wL8owfRVsfTM361858n02Va+UDIjmgNxJ5vMDL+x15p7ib1TGVOzCDUT
         6sQQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798764; x=1766403564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=b8b6VMtEEckrp9RjkOUSf5evGJUMqu+qh25lAgt5us4=;
        b=YGj40LINJI9lQvrbAjOqamksshDOmf577E5gzJJXMLvPcnn3BFttFl4lT700RQovXy
         Nj5ZVWQqcW1Noo1/iPttzGZxQKxRQsibbwRxs4sZTHhf+BgLbsXuJTg9YPNt7TGP0UWF
         oTwDOM/ULdGXHLcGHc4hdkYvbsPMeR/5sqDUEDggt6u6ES7dCF9FI1YDbkVUXXglPBPw
         Bzuf+biLtTK17SNzRhHCHhdgVWanfUGKdFtF9MGyKia5bgbj7sjnoQrJcNVobc8pTwt/
         WUM+av4GzcuJc6O7U4mWDR5lCTZ3/YWiHRWw2DrlRL56CvyWKNej7qxJLDCcAO1yGzsO
         nHXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798764; x=1766403564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b8b6VMtEEckrp9RjkOUSf5evGJUMqu+qh25lAgt5us4=;
        b=cgNR6kEPbhxx3gPDU+OVhvVrm444a2icrurP6AIVym7wfG7uckg9uRiqVjPRGAQ0Xv
         ZYDnmkwny9WKV0v7zACp49GXxPaQbKU2UHTiIdpucUmUNNhkTAAZyEYJ4ZZPGXOI7GMH
         S58qLDfspLXgva//lq356OYVkKiWTD5Oh9F6JiLOzefH1UUQ036nzPDosK4g4wAQeL23
         LHxjjPkitzfSNnpY592Dm2uyx7m6O9JcVWUZPo/KapeHfxVp5ZKMbzwbOOxE0SpsZLjT
         BtxaK3I9ioPoLNaalwnGEX2id7BsqROhyBgv4NEg+D9rlFXlKDb2AYdeY7Ob2viwkOhM
         NufA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWv18ns4GdY46VQqh8Nc0HJ6ZTL8GEV1W2Mjsl0ZCGVzEbf80qYhUpBPXHJnite93canLqWNA==@lfdr.de
X-Gm-Message-State: AOJu0Yw+By/0N6zvExna3OrM5qlEzX/3+i1Zgro85yY8wcQw2KXzKgoB
	pzBTxcjTZaIduNUrXYaZdJ8fXlRl1IYgwrsJjeUOkcP6Ee9nc1uByoC3
X-Google-Smtp-Source: AGHT+IH3nDR81ccm+BY6Z/upBgp8OigixB3TeOl4D47WEf7bRKcoX4iLUVW+sRl4SLJV45STVIGyKA==
X-Received: by 2002:a05:6214:16d1:b0:888:8047:e514 with SMTP id 6a1803df08f44-8888047ee92mr122247916d6.5.1765798764180;
        Mon, 15 Dec 2025 03:39:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWal8PsDH75w91M1+YwxvOv2Kt3/cHTh9ITbx7jNDOS9/g=="
Received: by 2002:a05:6214:e6a:b0:880:59ee:ba5 with SMTP id
 6a1803df08f44-8887cdc4713ls65853716d6.1.-pod-prod-02-us; Mon, 15 Dec 2025
 03:39:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXn47JcNqDVD4aPEcKjrRw/0Rkdt4+2fXqqodXbgHptO4mxJgVqJT7IioNdIMQzGYoYQnS1S1zQTWE=@googlegroups.com
X-Received: by 2002:a05:6214:3c8a:b0:888:59c6:7c43 with SMTP id 6a1803df08f44-8887e185fd9mr155181366d6.63.1765798763493;
        Mon, 15 Dec 2025 03:39:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798763; cv=none;
        d=google.com; s=arc-20240605;
        b=l3xPiaW3yBie0eUBShQ7Ra1btdhtDuyqgQxNaKQjQ81lhXBCiuyVM6o+XV+rspMkLV
         6o8aluk3dwnG0BHCykbwac85ZhkZHcEb/x853U9gAOQM2ELbRVNYF2pSo7vUdSCSfCTd
         EhozgLlZ0Ai/EGGXSiF6Fe8vTFqTJF+x5aC5h5xttIa7KIlDbtwC6xTLVUBV/RhiETCe
         1uq+pXklVi3fGxwP2LafagWPXcYKs18mNEvaciBOVq8jVLpf7wXUxn2Lqyz/KlHxWdyg
         nOU+AZd9sFr3L1y6e/q7F6JK8wZ3oNF9onaxWpO+ivBqHieBOYPbZ4tber3Fu33fG8TO
         mh5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KFsNe5Gu995f8GfU2RxaYzwbXM91ZCVhfkD06BV90tM=;
        fh=b0oYYifxCcYSYCLtqpRdsEK/7R3mCmtK1kvC0ec1eS4=;
        b=LymQowLB1VOSR8fd46skykuEehreBVfa7ZrX9pKOTBJw+GPifPoEQs7NU/wtXBHpWl
         666lfzHLlCvLGxig9ursAxh++je54K9iK5iwkBjsSOZcyO3YMtvxqjla5yhasG+bjCDf
         /rulVdPVYJaCaIaUxovUI7GC2IHfJL2tdMu2PBiUwW0qz3rgcDNfDBDd+ntlusMOc6+H
         H1QjgbTM26/4/A3wG5xGpRoTJ9Zm0mTpxO3Kr0WXLKXH5Qa/P4gBSk/CCYaRLzroF6VF
         //vbl58+vy+bP/7oWZVmgaeoah7mKPT06AUCaPLya8v17UvKLpxHEUF6poGQRH+3HXmo
         nMbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SfMeWQWi;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88993b3083bsi3153936d6.2.2025.12.15.03.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-29f0f875bc5so43957405ad.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUw/pUVonAzJwN4MTISU59UNkLo+E2IqCI21eXT27kYNGEtIFfUCRXiD9bIWDbltVkywcE/WCJ5228=@googlegroups.com
X-Gm-Gg: AY/fxX6MlY1V8gw9IoXiCEcl5q+00w+vS6A3K8OX0EKVPXjmFmMEBv5yV34jemDAOIx
	X+rU5f7WGsjsfBX6h7KeUSoBdyAF8OhpByJlNN/KabHdOzmqBVRElHd8CTpZyzbQ2/YUxzUxlG8
	ddLeKGOjCq2UPbCuqV6Pr7DvPk3hZGSiRmtXxPO4Fkh3xGMpECC5IuvS+r/nzaUUhLnwF94J8z7
	6847ukWujbeBZe9Pf2v8lsFBDFs97YbvIQQ/v0FjlD2z/bdxXL/PY19w3erhRhjaoyVWgOLXptH
	sUAn26iv2ZAy5rFJjda6JR9ktePFLn91yuSTRb0sR9rRAG8otCHAH1hrnAnTIn3xwIjFanX+IW6
	MDvLPqWWKaDvYEqtGW0rCzHwTTLcR3USvXjLYOzFLVMyiYS13ShP1UKcym5WoFn6gYkRLULDVQO
	1BeTF8VHpq+Y0=
X-Received: by 2002:a17:902:e94c:b0:29e:5623:7fc3 with SMTP id d9443c01a7336-29f23dfeb6bmr88540375ad.12.1765798762466;
        Mon, 15 Dec 2025 03:39:22 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29f2ebc340csm91145715ad.28.2025.12.15.03.39.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:18 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id CA7C1444B397; Mon, 15 Dec 2025 18:39:06 +0700 (WIB)
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
Subject: [PATCH 08/14] VFS: fix __start_dirop() kernel-doc warnings
Date: Mon, 15 Dec 2025 18:38:56 +0700
Message-ID: <20251215113903.46555-9-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20251215113903.46555-1-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1286; i=bagasdotme@gmail.com; h=from:subject; bh=XiWwx/yBvL5qhtur1OJ6r0Qtve5kN/UAKMQDFDv8Kk4=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4O3vI8WDrMwXuvBLq8mNivp3ZeuaVYeu+cJXRZ0u 9ehPPdrRykLgxgXg6yYIsukRL6m07uMRC60r3WEmcPKBDKEgYtTACbSG8vI8EpCRPb0s1m/77E2 hv9V7O9IOeS06tfyqjLP7/lK/+xuKjL8zzy7NtZA+f5K8VWm3d9utqf1737naLT7ZsEzs3nvY45 PYQUA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SfMeWQWi;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62a
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

Sphinx report kernel-doc warnings:

WARNING: ./fs/namei.c:2853 function parameter 'state' not described in '__start_dirop'
WARNING: ./fs/namei.c:2853 expecting prototype for start_dirop(). Prototype was for __start_dirop() instead

Fix them up.

Fixes: ff7c4ea11a05c8 ("VFS: add start_creating_killable() and start_removing_killable()")
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 fs/namei.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/fs/namei.c b/fs/namei.c
index bf0f66f0e9b92c..91fd3a786704e2 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -2836,10 +2836,11 @@ static int filename_parentat(int dfd, struct filename *name,
 }
 
 /**
- * start_dirop - begin a create or remove dirop, performing locking and lookup
+ * __start_dirop - begin a create or remove dirop, performing locking and lookup
  * @parent:       the dentry of the parent in which the operation will occur
  * @name:         a qstr holding the name within that parent
  * @lookup_flags: intent and other lookup flags.
+ * @state:        task state bitmask
  *
  * The lookup is performed and necessary locks are taken so that, on success,
  * the returned dentry can be operated on safely.
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-9-bagasdotme%40gmail.com.
