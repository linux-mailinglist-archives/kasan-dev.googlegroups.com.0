Return-Path: <kasan-dev+bncBCJ455VFUALBB5GLQPDAMGQEHF6CXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id D53BDB50B46
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:05 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b5f75c17a3sf109074561cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472244; cv=pass;
        d=google.com; s=arc-20240605;
        b=aDi/rziAHM7QLN/J8csKlCDrXODqKGz1UHiH0KoNqvqRDqaVW4gcaCXzV5UH/2L08L
         l9tkXosuM4E58mY1iym8WSILTVfABz/61r1lmKQeSQ+nAglLxiMPCF8Cn4m/BJRheDew
         mtuPlxQr3hWgPhi1gkQOkbhLbdQBD3fCAySUxP8JbIFy8ppFgdkESLpZXLTk7EEzg0z/
         TcHNtv2SueRS5sTeJwgMlZx3vrzer55wmXIp43RPEJfd14bVChp2qG/IXrqyJZX2hsQq
         /xUw1H2B5zezK0HdR4ZCXhdMQJN97PiMjD6HCMIsVrUL2740J9jgqrLLJASEfaZofVc2
         GD7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=zeJHW9p8hX74yfLP2NbagsLGnHouH4QD+z5a7BlaqTA=;
        fh=emNi8O9aJKNZgTExzR/OfO8pkGsGJ3UmKhMM+WBmQZ4=;
        b=QmrGQMhWobaW9jpfgPNbg409nTFcpaRv/LWB57CFlUH7tNIjojB4l1HQyOKab6P+H0
         tLJrPxJMUFMtlBYJ9wAhXMluPu4WHSs6H711Zy9W034jjsccikbXIg/Bks91+jQysGwZ
         4U64HKbOQV+K3c0zpU8mG+klm6QmLlmNdgphv6+HifMxNBgCi/FjyldJdc1lFT1Pn0W0
         RXijLPTdHPTi8IrRwkvE9HqfJ8/DT+8ufLm/DLQ1jh72yBQnczDc1fJqWpUhRrSYBuYW
         lWJkfsS9fryFPrHKTsXXzEUven9XWvMdQP1exlt12e6LwYPL/iDTKjCwX1Txlxwv1qMg
         xXEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eGj5apy7;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472244; x=1758077044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zeJHW9p8hX74yfLP2NbagsLGnHouH4QD+z5a7BlaqTA=;
        b=Ti+Nb5/OD6reo+JwlGoKV7/+Hjm7jaPtiEw24yr3T/TlsMKwL1cKHVy143nlXTvvtR
         astIv8fgLkJjtyIPI0wyOJFfI4DxvDDbGU5zIG6BUguLcISN6ATHK7VKfRbrvuQMbHqG
         UMs3B1yIjuUhcoMcag5/F6YEIkkGibRslvOeztyEjGd5RtC7Wg3OuVfzrVELEMT+Q0Xh
         h5lYyEgN1Q4aND0a9CYLa8rmMPkmofkS50VeKWk1U1zzRYP76vFOBC7jvdo1oW9WrFVs
         deGHjUpeHLlxq3yiAumPqMEcIOwgj6xpxiA4EVlITvf8dr34dxyrHCHeaqHrqp2Fqtvn
         traQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472244; x=1758077044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zeJHW9p8hX74yfLP2NbagsLGnHouH4QD+z5a7BlaqTA=;
        b=A9eeZZLhsZxLyH3/QPD3TkKGaVhf8Hni/m67FwDeipcE3FEr0ijBTAKszLs8BImhka
         6FZD9OTCFuWos4DG3+FutLHQ+RlPuGI276hSIioVbtYj0WJ3pSy8lk/JghZ+baRtW0BB
         NXQ8wy5Y6F2bPu4Sjq44ybiX+uMMb5+fn9MPKUdF4Vt3j6yU8PTKoNpS78u00MNDZKLx
         0RvqC7i65WcB2npb2VNU2emW4i1Nu676Bn3EtldtJkRuSNoBOr0BFyoiQ5OMIVL12L+q
         zq/injoSGiimRuC78riDtOOZVn7sKmGsSwwIdim3HKEcq2kAUM76JQNaURqFjJD71voo
         aMow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472244; x=1758077044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zeJHW9p8hX74yfLP2NbagsLGnHouH4QD+z5a7BlaqTA=;
        b=XOdZemxKB0MAzlqWlFBSdXZaoNO3fLdQDa55JjeaTEqmEWi8FPM8u3TW1mjlSA5H2P
         EIaDaPLCtfymxpaCzv0lB0X1wybmA0tR2sDqqgiS/0LQZcJ3y5zapUZHztVQBNfP6QhI
         VXBp7DfpWm+oViKkKeXCJQvtdpee+3BJ5HWMCKP1mzkPWdzMqTA0nkwV+OJfKIBubikw
         TEkRZebT3QW552qOL39cZvRtMPYt2Fp39NHKKArmAdk/HZcOF8gq2F1LJRXshsttePbP
         fGHhU79vpmWv2zaBMt/cznChfgmx0IaOtdmSYPk7Zh9aDtwWi0uNonT6VtIrJMlv2/bl
         1PlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1VFhzmUNx21jF4zWhsyO9fNpzwgsW+EC0WOCMk5QPnxkDuCLxcW2etHsMa4puateEwIXY9Q==@lfdr.de
X-Gm-Message-State: AOJu0YyEynDQud5xs+9I2eaWGVS96197oquexSHu5sqAr3VKdhctZaDn
	+UZkveE3bcPpF54k4x64OskL4yAi5y55u7gUS2jIQWYCdr/8UZrjskXC
X-Google-Smtp-Source: AGHT+IE5Up+Ppmr6rkww1EGxzYU5fbHwrrl5edq+GfG8jE0Ao0PJm9MOrSXXs2u3f6UhMLrEURrtMQ==
X-Received: by 2002:a05:622a:428a:b0:4b5:e35c:4900 with SMTP id d75a77b69052e-4b5f84bbfacmr108333231cf.80.1757472244684;
        Tue, 09 Sep 2025 19:44:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBsFWZuv5ZPmqwTYF9o7GVQE6lcDWP8EIske8Cp15rqg==
Received: by 2002:ac8:7f91:0:b0:4b0:907c:917b with SMTP id d75a77b69052e-4b5ea8d3760ls86675981cf.0.-pod-prod-07-us;
 Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVH58Tn7o7BMo3MaTJ0cFh0ydR/k85SP9Pe9waWve4NSpJmkUkAx0c9+HB2/ma6bpQYdNQ0fxhHPbE=@googlegroups.com
X-Received: by 2002:a05:620a:4707:b0:817:989a:b1d8 with SMTP id af79cd13be357-817989ab2b4mr924303285a.25.1757472243742;
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472243; cv=none;
        d=google.com; s=arc-20240605;
        b=Zv6AHPhd468EE2+D7bX5S/UKYVhqqnIfrnAjsIrJNgDkzeyRs5iznc/nX945+3PFXV
         afqtAQtSr9L3I/mUb2raeCoTaZ7EcFACJWZ5qwxek6D/mx+JYrVAsQjEYcVrRmcC+FmG
         ekFGsk2AoQGvac6IFUY4hAsib8pn5bFyTTkOG6VvSPalQc6Cl6oxaLv01tHWvm13nQ4b
         Yewvos0hJjrgC3RRSWLog1QXGFe1QYtyXItOWa/OzFIQt4n8+/EiWQq0ptk+nRWBqEyn
         7CAqUhl3wBrUclcPZnUZAs0YimhbH/q10hWqneOzMZpTixG8+aY8eUI4O/z1iqYaUgpj
         xFkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rNDvUkQSM5YXWXIzm38SWG/hRRo/bsx6SYKE7k7lSmY=;
        fh=7efFJi2XC3BumT/r2/1KBTO0wrbtUDcJPTmv2voAwfg=;
        b=Zfk5Be3oj7zgp9ntl95Jn1MOmPmfSWQ662mR2pFnwZO8xjIsfPNCUJ//7Fp+T7qMl1
         y9ZUJjRp5PzDFIboTwHRDVae8ZVK5b46h8+/C+38mQCit6JLKVvoPhsGqMpE0lnXZoGe
         1atTMhRePz/umCJmMTWBXkH9ecorbs+0uPd3UQoWeiq5jCNum4w1X29rYo8SzoIpC2sL
         BvtfHxuKZEMIqg1fxQ9yBAnDYc/fv5ehCnP11CmzYKWK5ln+WGdbn1cZ5O6tDsWD/+lS
         PupvbytMCJfQvLmBqxmeKSMdtktgSE4ZO1BxAWMnwiyLI+FzS9oUG2BPFeynavxgfmgb
         9i8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eGj5apy7;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-81b5c31e722si16261285a.6.2025.09.09.19.44.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-76e4f2e4c40so5023417b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVMxsEuiYyv30lcaajcxAueP3MPWZkevni4gF3pr6CsNG3ZXs1XcPOxhau5pJQro5k3A/R0RFwe2Ts=@googlegroups.com
X-Gm-Gg: ASbGncuKYbcA6PgqfwhxdfvzL1qhFFanXhP4H+mm9j/QDfT7V3xYhetpihYaEGHXAVB
	iyRTOghsFgUo1nnkhzW8YlOZdPFqDY1QY6nLuALFguAmqUIwtSGTibglF++O+QBM3Q7GaFeNwoD
	dmh65IcfQ6o2Gjt0Vvf1KqkBIrCY9HFxVXoLUsRDVIzLzlretl/QgFJ3aTrfJcJp4oqp0+77O87
	OcGMFy58FwUnnOV3FdzE+P5NXG82vcBDc2saITPpZTGU0qh1yDBRrZ0Qc5lwtkyde52/qzOzZL5
	lqyKuXUTIcBywy0ozWC4JYAtXMngcgBJf2joIP+flXgkbIS6YCV+s9f6SeGOZVpxTmZqm8QKb5r
	zoid9lfoKJykyRd9EG4LRB5rDAfDmqjSlupUV
X-Received: by 2002:a05:6a20:5483:b0:246:4bd:b1d8 with SMTP id adf61e73a8af0-2534338b026mr22737333637.32.1757472243076;
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-774662f7f1csm3488284b3a.97.2025.09.09.19.43.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 7D27041BEA9C; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux Documentation <linux-doc@vger.kernel.org>,
	Linux DAMON <damon@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Power Management <linux-pm@vger.kernel.org>,
	Linux Block Devices <linux-block@vger.kernel.org>,
	Linux BPF <bpf@vger.kernel.org>,
	Linux Kernel Workflows <workflows@vger.kernel.org>,
	Linux KASAN <kasan-dev@googlegroups.com>,
	Linux Devicetree <devicetree@vger.kernel.org>,
	Linux fsverity <fsverity@lists.linux.dev>,
	Linux MTD <linux-mtd@lists.infradead.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Kernel Build System <linux-kbuild@vger.kernel.org>,
	Linux Networking <netdev@vger.kernel.org>,
	Linux Sound <linux-sound@vger.kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	SeongJae Park <sj@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Huang Rui <ray.huang@amd.com>,
	"Gautham R. Shenoy" <gautham.shenoy@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Perry Yuan <perry.yuan@amd.com>,
	Jens Axboe <axboe@kernel.dk>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Andrii Nakryiko <andrii@kernel.org>,
	Martin KaFai Lau <martin.lau@linux.dev>,
	Eduard Zingerman <eddyz87@gmail.com>,
	Song Liu <song@kernel.org>,
	Yonghong Song <yonghong.song@linux.dev>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@kernel.org>,
	Stanislav Fomichev <sdf@fomichev.me>,
	Hao Luo <haoluo@google.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Dwaipayan Ray <dwaipayanray1@gmail.com>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Joe Perches <joe@perches.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Rob Herring <robh@kernel.org>,
	Krzysztof Kozlowski <krzk+dt@kernel.org>,
	Conor Dooley <conor+dt@kernel.org>,
	Eric Biggers <ebiggers@kernel.org>,
	tytso@mit.edu,
	Richard Weinberger <richard@nod.at>,
	Zhihao Cheng <chengzhihao1@huawei.com>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Waiman Long <longman@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Shay Agroskin <shayagr@amazon.com>,
	Arthur Kiyanovski <akiyano@amazon.com>,
	David Arinzon <darinzon@amazon.com>,
	Saeed Bishara <saeedb@amazon.com>,
	Andrew Lunn <andrew@lunn.ch>,
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Ranganath V N <vnranganath.20@gmail.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Jani Nikula <jani.nikula@intel.com>
Subject: [PATCH v2 06/13] Documentation: bpf: Convert external kernel docs link
Date: Wed, 10 Sep 2025 09:43:21 +0700
Message-ID: <20250910024328.17911-7-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2744; i=bagasdotme@gmail.com; h=from:subject; bh=IiAjp2UiG4E4i0m+2wynqH3PCAcCcaK0of1KdBtx1KU=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnii1Whs7TnrT1LggM0BOd5LEqfAiXtc37zS3e5gl8 vnwGP7sKGVhEONikBVTZJmUyNd0epeRyIX2tY4wc1iZQIYwcHEKwERe5TH8D8jY+cG0Uf3udDP5 nmfVwtmWi5mup+fF7AiUlLjK8OXNJ4Z/BmfN3s08dUKM70wua9O148mfqhVc3wuvO6WtdrV4s/k pLgA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eGj5apy7;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b
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

Convert links to other docs pages that use external links into
internal cross-references.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/bpf/bpf_iterators.rst | 3 +--
 Documentation/bpf/map_xskmap.rst    | 5 ++---
 2 files changed, 3 insertions(+), 5 deletions(-)

diff --git a/Documentation/bpf/bpf_iterators.rst b/Documentation/bpf/bpf_iterators.rst
index 189e3ec1c6c8e0..c8e68268fb3e76 100644
--- a/Documentation/bpf/bpf_iterators.rst
+++ b/Documentation/bpf/bpf_iterators.rst
@@ -123,8 +123,7 @@ which often takes time to publish upstream and release. The same is true for pop
 tools like `ss <https://man7.org/linux/man-pages/man8/ss.8.html>`_ where any
 additional information needs a kernel patch.
 
-To solve this problem, the `drgn
-<https://www.kernel.org/doc/html/latest/bpf/drgn.html>`_ tool is often used to
+To solve this problem, the :doc:`drgn <drgn>` tool is often used to
 dig out the kernel data with no kernel change. However, the main drawback for
 drgn is performance, as it cannot do pointer tracing inside the kernel. In
 addition, drgn cannot validate a pointer value and may read invalid data if the
diff --git a/Documentation/bpf/map_xskmap.rst b/Documentation/bpf/map_xskmap.rst
index dc143edd923393..58562e37c16a01 100644
--- a/Documentation/bpf/map_xskmap.rst
+++ b/Documentation/bpf/map_xskmap.rst
@@ -10,7 +10,7 @@ BPF_MAP_TYPE_XSKMAP
 
 The ``BPF_MAP_TYPE_XSKMAP`` is used as a backend map for XDP BPF helper
 call ``bpf_redirect_map()`` and ``XDP_REDIRECT`` action, like 'devmap' and 'cpumap'.
-This map type redirects raw XDP frames to `AF_XDP`_ sockets (XSKs), a new type of
+This map type redirects raw XDP frames to AF_XDP sockets (XSKs), a new type of
 address family in the kernel that allows redirection of frames from a driver to
 user space without having to traverse the full network stack. An AF_XDP socket
 binds to a single netdev queue. A mapping of XSKs to queues is shown below:
@@ -181,12 +181,11 @@ AF_XDP-forwarding programs in the `bpf-examples`_ directory in the `libxdp`_ rep
 For a detailed explanation of the AF_XDP interface please see:
 
 - `libxdp-readme`_.
-- `AF_XDP`_ kernel documentation.
+- Documentation/networking/af_xdp.rst.
 
 .. note::
     The most comprehensive resource for using XSKMAPs and AF_XDP is `libxdp`_.
 
 .. _libxdp: https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp
-.. _AF_XDP: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
 .. _bpf-examples: https://github.com/xdp-project/bpf-examples
 .. _libxdp-readme: https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp#using-af_xdp-sockets
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-7-bagasdotme%40gmail.com.
