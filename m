Return-Path: <kasan-dev+bncBCJ455VFUALBBXXG77EQMGQEJFWC2KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B4873CBD857
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:39:12 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ee409f1880sf6723151cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 03:39:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765798751; cv=pass;
        d=google.com; s=arc-20240605;
        b=ci5yqrynq2wBgEQj9RAWgyTsJd52milbme5tdFo4c37W6lVC3+Xglu2u6Zw8/3YRXS
         uTAdLwRWvRMm+259w7NKgUSOjeRibVuWMEPFNL0JlAvgKRCVCqS7qaqLwxACXmezwu3/
         O5z5RZ+5O4gJMH4JBv7TuN6XShpbFa5wrIIIlROlsM87IL5dlgw5XDRolsambVmQUI88
         5aSh+N2VaLPsEPk9mb5KweHy4PfE7sJaxDjzpb1iL8EiMzmfE3FCNDr5fBzc3LvCvVoy
         jjKIjuksl3YO54FqMdPQ+S9OT97UbXJUU6L2EIwyzXdZF+XNKt+7EfuoBnDKEyx+RmEw
         PPWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=slW+8ujhUU05a7O+jDuJs3jbN+wJdh5WHwVIM/jXXjA=;
        fh=UW6NrCctbv4E0Agq6anf0L6g1rrOG6EqTRlYDR2hgd8=;
        b=IXcoxBtw6FJUEpncr8IjyNtLFT7Xr84qOc1RGuQqdPRGIWTe+rJrMorscnQ8MbniJu
         2an7SHDWVJ5FyEyJlrIXs8BSkpoVe/lHAjOpD5qYaK4nGZ2VfiU3jDNIC5XJXBJ1kmNB
         DsTnMgbpk3Dc+lSKjF++9ICczRTc2WG5GaZ3HGVA9p4FzqeKn8ELqHF4HtBFdji3ZyJH
         fDqaiMvM1ia+3lsAHLYJB3wTER/qyFmCPiniLiBXJ7ep7KbvGYmytK4hZNPZoCyqrNgw
         eAnCKgoWLFQDSpS2FUZ2orEVJ8OJpKF0c5KmX81+BZpRRbynon/iUt93oPXI/KHW3tx7
         jGNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UQtv6Gor;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765798751; x=1766403551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=slW+8ujhUU05a7O+jDuJs3jbN+wJdh5WHwVIM/jXXjA=;
        b=PIPccFAoBTxUHgKLJwOBfSK+Z+5YAwG3mlVW4ygfeeXm+jTJNl4yhDSHAEtzgeMa8u
         hCmL8y4ciFz+RIEshS9e/LyqDtWblJibx0WkSRelkYZTTXtrGTe1k+B7LZbcZUVGEtRS
         Hq/cN31op3o7vq+cbo7DBHWTrKaow5LwhLatqbduLLctLUWO4+f9kFszmW9bG97AQ0bu
         fcmNuXl5PWtRZkzYylF5IRLYXoH5UhVCCqPEbk1P336h64asmqE6vnhwaAhVho4z2jqT
         lzypcLXKA298K+Ko90W2Sh2lajQkqyw0bGZtFYbMbub7A3nGxdU232HNXy7bKeFEkx6P
         gT+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765798751; x=1766403551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=slW+8ujhUU05a7O+jDuJs3jbN+wJdh5WHwVIM/jXXjA=;
        b=GQvgclXEPIGJSzSGGLisrcuirmJEwpDA+POaRvszc9Y9GdTSTRm/QnJcKZ46qlf5yQ
         8WoJjlEiAKXRTvdb0JSCcUQ6P1f9Ivz5rHBnXzM41/FxtZvAM/G9TltocahCW6pqDXSJ
         Iyf+k5k8AoIDhKyCiU1LkoqBUeebuAnNooY86n46QKKNtpXIAim5Q5Tplnk+U61v3ZLH
         E8xjWmW8W5LMwhKJNTWQy4oCQzNgKvvjxBaJDKNUGOg+DfaFSLRh/yeQnQj0pXXX6WQT
         qBf6rHSTjdKuPdP69L79TVUJHpKqEJHojYSsm/kIkF7PXMOn4ZQuo1nEFC0YkmMmPsRo
         OdHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765798751; x=1766403551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=slW+8ujhUU05a7O+jDuJs3jbN+wJdh5WHwVIM/jXXjA=;
        b=kkcoFRXHYzTncX9jdcLH7pm6g32DFLsywiiZpR32fuvJsZW+29BgNiwvlwJK3L5M7t
         /bK2OAanDJ5nhGdVDZrX6FdLvleXxbF6TmHt2gJq3DJ6sgprPw4QgcsZiRpNlCzD8rkM
         My8WdHW37EIKkZzgA7QD1QCE4xt5Qxa7wvplUbhLcx0tl3RVa9UpDBb+38x3jNZ+SnPW
         X2ZB4h6v4ofVghe92aaNAEJbUGoRJGXvXVhV9VQmJIPrWzJP8czytwXZkkx9s1goIFEn
         fBzwbITFyq+RNFIT4T1tpSVePcu13WX0AQ1AtfySqDeLnH9kyJV/uLBo+sVVdjszQcmM
         SXdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxORJT5qTKACFeayORG+NW1HsL/2ByUtRDbh9YULGuBwkyfy9jSOoydOyAEnPkB3JxbbRQxQ==@lfdr.de
X-Gm-Message-State: AOJu0YwG9a2B/njXK3Vp4XV8xtFxUyuE/99tGsejGTCui4i6Y+vhQSyF
	+SKgMmRfN1+9SxoA90xZ5cHnxWosYa4ZPxITDc4+X74Bi2IIuVoFAdQ1
X-Google-Smtp-Source: AGHT+IFZeU4jSsdns/tHU+jwSr0r35QiXc1p+MBrA1EznVR4cyOHGf+OplN1n2zcs7ezgkytIhdLyA==
X-Received: by 2002:a05:622a:102:b0:4f1:b580:fba8 with SMTP id d75a77b69052e-4f1d04e6df9mr112720481cf.3.1765798751123;
        Mon, 15 Dec 2025 03:39:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYsSbK2/YJtigHKChwew6GSFIY22ee4T29yH9svQu9N4w=="
Received: by 2002:a05:6214:f6d:b0:880:30f4:d339 with SMTP id
 6a1803df08f44-8887ce12c8als66016616d6.2.-pod-prod-09-us; Mon, 15 Dec 2025
 03:39:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXcvqPzwvMtMO9DbcJu2ZpLpGLS1pxcVvha9xrjeL0cDS5MYA9WG8bLvt3giIB/3F7yLcFt8KU+bow=@googlegroups.com
X-Received: by 2002:a05:6122:3d46:b0:55b:305b:4e44 with SMTP id 71dfb90a1353d-55fed667a3emr3321292e0c.21.1765798750273;
        Mon, 15 Dec 2025 03:39:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765798750; cv=none;
        d=google.com; s=arc-20240605;
        b=jFsYYGSfLFbY0tFHaGfi9KYR2meOV69ta66yWmlZBs/rvRX3qkiXqe0HVd59eeW2M7
         Qa9p19NgJLYanBUyAqqxsGhRW+6y4v7VXYJMXxklNtwS2rptCNK+U9RiLq+TasM+911X
         FCiMtBjQfvZPPf3nFDPCJXUC1ZoOVZ0W9KmOiehm6gwbBlwYXZRKNME5MYIX7t6gjSXb
         N1GDC3nDuvfrqARnQufvPXgBszJ38UBRWipvBcXnZme3hj+BF3mLV/Z7pzBc9dLbAwF2
         hDWsqJ3FCcraq0jfQz4xNXYFNEa/bg+KaKikoXlrrUjkPYt9uhUddMfyJbPSYpGpOj59
         t4DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=rTcY4k7PJNNctnILuEp0lcvqj1X2scOTc/Z894ZNYfE=;
        fh=vmrJ5K4YwAwo4GpiZDDDEljPEWrae7U+G9wUQ4eav2M=;
        b=NWLXaz1NGJL0nstzCRfGzRCwCoRtwm1INjmQdWx/JXjhJw8MCX7cvdaAUW//45+B+w
         FTqSnGkdandMeik9EldZBafegPMufhxb3tWGIJemD0kXSl3SDpKwCXZsJ+aZ8Nzdy0bv
         b3nHKb2NiKuQ342cODRmIEqrxQExISNt/MDh4ocGHYhXwjctswZ8AxOs+6ciRBdehnU/
         K6dvQpHB8P2XU7e9tHR276bRwA0Znbc2m2gXBgCwL6+kJtr4LLAECuwgIwVMo5g6sH4O
         99JuwtFjt4qsXImiLmty2VLzPu0KSwUZNblDsRAwFhPgRbJ72iReSedUhzxV5IXuZC1q
         syxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UQtv6Gor;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55fdc47fc84si482407e0c.0.2025.12.15.03.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 03:39:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7aa2170adf9so2622219b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 03:39:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXF0yKvnYOF8KtarTe2GJYbWp9OizAgkNW54TbyL43oBeCg3DZ7XEHQfILdRv11lsjDNDDgeD4d6mU=@googlegroups.com
X-Gm-Gg: AY/fxX5XsTNYBSdNTTHigVNsuZGC5gbGevWXji8JBJdWtvcBLYGsyfcrMXqcqTnOREf
	5aTKbV8anx/iF0yEtv2qRycGhyznAzcwOw03+1hJUrJZPpWWa80sXLOK79hT/qGvfxoJdMgLzfl
	iphPpoNio4JibDDNH1kLDiJQ+YhMd8/hRn+3717QPAOcdnQRFhoCZQLUOWWWBSHk286u87dLMiu
	xFta1zzZZddU+BsnCWRFsqP9IXolOInygIYFW1hII9oR6ur8Aow+ctWm9YnKOoiT3eaN1acS6FW
	gutAhi7EKB+sG8c+6LFRTLPBFe3O6lznAFpJddsFcCGPo2iiPZ5cE4vbObCr2kWRXJ0aFVyiK0W
	09rPJXcWjGQG0s8irpekJRFpQg5aekafOJTFQuO41EhqaZo6sRuKPVDmbMl00xrYC/jlpUDMs2/
	Ag1bUBth3GtKw=
X-Received: by 2002:a05:6a21:3395:b0:34e:865e:8a65 with SMTP id adf61e73a8af0-369af528581mr8834767637.52.1765798749224;
        Mon, 15 Dec 2025 03:39:09 -0800 (PST)
Received: from archie.me ([210.87.74.117])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-c0c2ad579b8sm12815345a12.19.2025.12.15.03.39.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 03:39:08 -0800 (PST)
Received: by archie.me (Postfix, from userid 1000)
	id AC75C444B38F; Mon, 15 Dec 2025 18:39:05 +0700 (WIB)
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
Subject: [PATCH 00/14] Assorted kernel-doc fixes
Date: Mon, 15 Dec 2025 18:38:48 +0700
Message-ID: <20251215113903.46555-1-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.52.0
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2064; i=bagasdotme@gmail.com; h=from:subject; bh=zPsruu4atyDYOaQCsKIEqnFkDKfYqb53HHp2txNqt3A=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDJn2n4MMm/867RRu9s/LeXucS+TRacFsjy3x8goRK//G7 Jyfu8O1o5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABOJ+cjwP9rl0j2O1i3mgnEF j0tV/6z5nLTvdKmsJY/NvB286XtLTzEy7D+8+dTHe63Sb6bPXnHWT1NH5vPMzba75Xe45yw3OaR ZzAUA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UQtv6Gor;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42e
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

Hi,

Here are assorted kernel-doc fixes for 6.19 cycle. As the name
implies, for the merging strategy, the patches can be taken by
respective maintainers to appropriate fixes branches (targetting
6.19 of course) (e.g. for mm it will be mm-hotfixes).

Enjoy!

Bagas Sanjaya (14):
  genalloc: Describe @start_addr parameter in genpool_algo_t
  mm: Describe @flags parameter in memalloc_flags_save()
  textsearch: Describe @list member in ts_ops search
  mm: vmalloc: Fix up vrealloc_node_align() kernel-doc macro name
  mm, kfence: Describe @slab parameter in __kfence_obj_info()
  virtio: Describe @map and @vmap members in virtio_device struct
  fs: Describe @isnew parameter in ilookup5_nowait()
  VFS: fix __start_dirop() kernel-doc warnings
  drm/amd/display: Don't use kernel-doc comment in
    dc_register_software_state struct
  drm/amdgpu: Describe @AMD_IP_BLOCK_TYPE_RAS in amd_ip_block_type enum
  drm/gem/shmem: Describe @shmem and @size parameters
  drm/scheduler: Describe @result in drm_sched_job_done()
  drm/gpusvm: Fix drm_gpusvm_pages_valid_unlocked() kernel-doc comment
  net: bridge: Describe @tunnel_hash member in net_bridge_vlan_group
    struct

 drivers/gpu/drm/amd/display/dc/dc.h      | 2 +-
 drivers/gpu/drm/amd/include/amd_shared.h | 1 +
 drivers/gpu/drm/drm_gem_shmem_helper.c   | 3 ++-
 drivers/gpu/drm/drm_gpusvm.c             | 4 ++--
 drivers/gpu/drm/scheduler/sched_main.c   | 1 +
 fs/inode.c                               | 1 +
 fs/namei.c                               | 3 ++-
 include/linux/genalloc.h                 | 1 +
 include/linux/kfence.h                   | 1 +
 include/linux/sched/mm.h                 | 1 +
 include/linux/textsearch.h               | 1 +
 include/linux/virtio.h                   | 2 ++
 mm/vmalloc.c                             | 2 +-
 net/bridge/br_private.h                  | 1 +
 14 files changed, 18 insertions(+), 6 deletions(-)


base-commit: 8f0b4cce4481fb22653697cced8d0d04027cb1e8
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215113903.46555-1-bagasdotme%40gmail.com.
