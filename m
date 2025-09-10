Return-Path: <kasan-dev+bncBCJ455VFUALBB4WLQPDAMGQECXG7NCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AA3DEB50B42
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:03 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3ffbe829b60sf96325485ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472242; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z6Sf6p/jk2Cr18DcTBXVwx/2/iZ2ksyJD/ddC3lTM9ki/RjOV/2Ko6UrSAakHZtotS
         m6jtDeu18VtnH0KcJAgq6nkJSrfRh6Uk9v6GvJSmqywTzz4QyMPOZYufpIrCmizu6kqO
         kkjmhbAPeYcGXwORZBBmg7BCC2F0gqK7a3y7jt06cQPTfAGMcRo+InKVvnxU0pzfUBob
         eAJdWdKOkhbJHr0Y92KcBPNYvTpWlNnv9xH2bjUmtI9PdXb78OsIY8R6Yd48sz7zKV2e
         XxeyS4D2R4jyLjuhCKd7RbYqIhBPSwaJnDOD62NwfX1bZKVKfrbq6To4u+75Z5YQFifd
         FvCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=5YEbJ7AKZ3k3OH6KhWUL/eG+D9De+rX2pcFVV77j2cY=;
        fh=g6bttfXmaLVKQ7EWnqQZITjPWQzPkYYes4NAqseyV3Q=;
        b=OO9GYwlQ/lAMwElZnPVlmxeL1VC4mIPVWombtVM2vs+yJYeK6PsnILdDdB2qpQpCWX
         UkXsFFm6UIUQ8r6lyEPaGQxAzF4pUgWg1cJ5oA5FK3kcF/hGkW83YSSHLlHwnk2cGw/W
         os+X6/gjUuyMDlrfxrLDzGljtN8zX/t2V+wy3sbydEDJV5jjCneWK6vUTKFfGzTKwWlg
         TzhcjGwpn70ekEA/B42iq7EeeqghyTWdqfCPyIujzgAfLMkhw14epkOjIOV6xkLpoVWF
         V6iDxa6tqSkFs7MlitjtKn3W9DWNkpiWo2Jv+1O6aGYPd8Lsj/JZfBVwcrkHMY+S4GJb
         tOHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fwlPC6ta;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472242; x=1758077042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5YEbJ7AKZ3k3OH6KhWUL/eG+D9De+rX2pcFVV77j2cY=;
        b=WJfyfUPgj6cswHcKbHjuqVoIj6erdWNmUr3i16XMvkwNBYkF5BodR7mEpZypU86L5p
         yibSKa+lEeUZlffdmw2Ql5LeUynYrwRnO6xtJj52xU1AavdnXRysEG9wCuIJdTjGYURg
         2ZjSuo9wP1Br4Y94OTqSyYuFod8ERRS74NdP0nfoNkPlsQSl37pPLNpefGAXifi2/w32
         lF4bIFSymbHmv2874I8fq4aijWbuS4ROF0n88in6y1lfiCwqn5ERA+rug8is/XcjyhBm
         6YzOd7OLAS9THPmN6fbj0ofgyMZb5vVJagh5A0cxv4WidxAjAnOUFMa2AlwQ/Nw+Sa/2
         8Bxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472242; x=1758077042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=5YEbJ7AKZ3k3OH6KhWUL/eG+D9De+rX2pcFVV77j2cY=;
        b=EZ7ObzO2KFvvxn43463OIlpjaXEAG8foJKsMQo3Kee2yldmFNgkeDWQTFf3mvAQn0o
         yDDk9HexsKxszwbAtoHacJBmwEGmrbFQeGTTzAE8GnlovVmGPPcTkJTDjMhtWdvfy/qu
         t7wczINC8q+rri9+0Pp6XbhBq65Ef25Ne5UKwUSvRSJjdQiuV01OGUc37zOJ/XEoVdej
         KTcxUZhDiEBqBP4ik7byo0N35/ccK/3Vd3xT3ii4oEPUKj59EdEy+3ZlLE9wAwgv9VPP
         6+RkQ+D30+tk/ExQMKDJudRWr7BUlB6dHKxNEATCpFze26LKcfjjAUh9W07C1AvaLzbL
         uVtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472242; x=1758077042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5YEbJ7AKZ3k3OH6KhWUL/eG+D9De+rX2pcFVV77j2cY=;
        b=Q1xcWa/XCjvY7ESmTNbSIePKEEf9erSZ18cDqBoObkAh3hFiK9BDaNJOXlhj42IpUZ
         TUUW+BD67GqvJvrDkTsgvHc4l5ooyGySOumwl5x5RYKC5CPufnrThaT0TaS+U+xgdIwY
         /QP5gLb1zJRFLKI1YZTsfXO1nVNVkaZGSylC5KAIxZrwMD/NlOTcRSuJuIqU75qHo1eq
         Vp1mv5QrzToCTJofF+ZMOxqeomSmmkfpLIY8nvsQrd4jtR17M/yBLDPWOkVk9wKR+GCs
         WPM0XVXaibG244h/NP/PUxWiJyl/NwCQCtJWLqbeDBIy4vAkpch2xuPVJjDsQYC+3LZ/
         41oA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXn/n9IxRK+3CKhTM9Be7g7K0UQDNTvGUk9brXdUz7RK4jzGhmd6Bfs1PkBdOWbpWGRW2d7XQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz47cm3RrzfhOzAu09QV2aZGaOJ61pmX0QyqHgwaN1Ew+mAmHTe
	btrGyg+/YZ+eD5QuV7Z9Cu4PuydEnX0SLjHYEK7anXmGlbKdUsy3jWi/
X-Google-Smtp-Source: AGHT+IFTyAvAeatogEEqQJoxa6QF/4jmKOq4tEFSBw6rxDvLTBOQozlLuS1Vc6MhASOlN+U1K906lg==
X-Received: by 2002:a05:6e02:1707:b0:415:a56c:843a with SMTP id e9e14a558f8ab-415a56c8606mr40332765ab.14.1757472242350;
        Tue, 09 Sep 2025 19:44:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdFlHC3u7ZrLq5bripzvZ7ouIf031SaT5Ts8fo0DJpCvA==
Received: by 2002:a05:6e02:d46:b0:3ea:468b:481f with SMTP id
 e9e14a558f8ab-3f8abc0c070ls3391625ab.1.-pod-prod-05-us; Tue, 09 Sep 2025
 19:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLkzkjEbQr0Ia+tUjsSzEC+uLKklWaAoT/RoqysRu/zsBWzirP4Lyx7eStlq4VZpXPqfMwpPPwWeU=@googlegroups.com
X-Received: by 2002:a05:6e02:16cc:b0:3f6:5568:d685 with SMTP id e9e14a558f8ab-3fd965c6d9amr216817565ab.28.1757472241078;
        Tue, 09 Sep 2025 19:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472241; cv=none;
        d=google.com; s=arc-20240605;
        b=luGLIL0LM3OFDTJgtAw7ssgnKVmmNwTIz/i+pYCtYk9Khb37VNxojBjkylpJxUn7lo
         1mGuiqElCDw2pQB+E1ovOA4EHxSYLSqwOd/OdVQ6uL30Kabg1LBbp90giP4XoAoHCWqU
         aKdditzwTP+I1qCH8TNiA+BLpFTUiwihEv+r5UyhqPNE1JzcguV5x2nvnSOOP3v6GhOh
         +7zF+VHOa7AUvef5y/a/6tAInqwDEInv+D+EzP0i0RmTRUJRwfLHDdPzfsySDoUbgBJh
         yuVenrHjOkFy6sVxOU1ZLxECVWKT3XLoBAOmt+/nFtymwYZnry5ECtToYUEJiyCGXsIK
         tntg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=exY9byyl4etH+4IQEKnm6qXO5lYPceGxvCuurSN7fh0=;
        fh=YKwJZfarUN6qFYSpYS95ruTS5G+aPJj/gWu0obxu6oQ=;
        b=F+eHsPCL9hBp3s6rvKnbe7/SaSBSNrSxXl4mGy0gRXsfXaDjKoviAcxVHR5zOm+3dG
         zGgYWB+EnspPKRTspunv35TKQqnIBYe9ur7zuknAKHbfjlE7b3gxY7CbcC9mzwoDH2TO
         qZPSpjWItU3wyqZQHhc4wPj3LRz98YRiMDE2Z9Lm9VN3fESBptshqDwKt6bdTd8hPCvc
         9YroAaev43el8NvJkZ3EUZ0DSude9K7OMuACYOw4oXNz872HdXVL8qiT97XcnlweuLBG
         zk2bc4BVtvCR6vjUrRkVvu+HNDaHKUqsDZZHOfdWIPcXGmFBXWTpHWeIQprGqSQmoDRT
         34Vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fwlPC6ta;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-51021bb2ab8si856924173.4.2025.09.09.19.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-7722bcb989aso4750354b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVBzWblhQZeOUrHxhQrvtl6OF8ktPoCilpZ8vbOlzRCBwc7P2jfGCj3e4d6HW04XPR21fN6QwPxMHc=@googlegroups.com
X-Gm-Gg: ASbGncsA/wKktibAT2C8296eNuPGSsxi03wOHNZZY34Fv3WUv/Kw2a9413Gnk5HownR
	ZtMXl44I7kHvB0iR5AZO6xhsLcOYB4wleeYXcnZGO9UZJUYJYkBrWWfHgLQnO08KTNChsp8etfR
	kvNxFoj21tcYME34OSYCZvN+fnsU1Y4bure2zLlGTyBa/EBkx1LCyr/17RTItro0W6lhAJja/Mh
	pv2gQvLatjwlkwWZnzeVUxXc72Sr9b0x5uONWupVomU3aXJp2NDVN8ICKw+QctUcAMjvq8lzTev
	wZNQRKt3U5BM0ExRLMMQF/YkDWj5tRjgoo+GYtNYHj22jhe+Vn50hwRhuEScVrecxDKNUJQLEK8
	XvXz9CIIv45omVcIy8MUrrBwW6GfDVeXRcWSC
X-Received: by 2002:a05:6a00:4652:b0:76b:ef44:1fa4 with SMTP id d2e1a72fcca58-7742dd071c7mr19532741b3a.14.1757472240481;
        Tue, 09 Sep 2025 19:44:00 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-775f6b4202esm573746b3a.55.2025.09.09.19.43.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 614CF41F3D7B; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
Subject: [PATCH v2 05/13] Documentation: blk-mq: Convert block layer docs external links
Date: Wed, 10 Sep 2025 09:43:20 +0700
Message-ID: <20250910024328.17911-6-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2751; i=bagasdotme@gmail.com; h=from:subject; bh=7QXrNRuCbHeHgCYdGUN3dSXlo+bJ6ZwXyeTt5Kf+8Ys=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnijp3TFftH6q+kyOiIzsCLYVR/ZOd/GUnnS+Yu6/k 6t6/fl6OkpZGMS4GGTFFFkmJfI1nd5lJHKhfa0jzBxWJpAhDFycAjCRydwM/yu/ZhfqF9YvP7NL t0p2f917xpei8yqP3w+TKtx3xMg27gbDX5mQVefmZ+9qe6G15Ils7rRL855MXJGSeHOCjN6Gx61 PyrkA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fwlPC6ta;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c
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

Convert external links to block layer docs to use internal linking.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/block/blk-mq.rst | 23 +++++++++++------------
 1 file changed, 11 insertions(+), 12 deletions(-)

diff --git a/Documentation/block/blk-mq.rst b/Documentation/block/blk-mq.rst
index fc06761b6ea906..4d511feda39cfd 100644
--- a/Documentation/block/blk-mq.rst
+++ b/Documentation/block/blk-mq.rst
@@ -87,17 +87,16 @@ IO Schedulers
 There are several schedulers implemented by the block layer, each one following
 a heuristic to improve the IO performance. They are "pluggable" (as in plug
 and play), in the sense of they can be selected at run time using sysfs. You
-can read more about Linux's IO schedulers `here
-<https://www.kernel.org/doc/html/latest/block/index.html>`_. The scheduling
-happens only between requests in the same queue, so it is not possible to merge
-requests from different queues, otherwise there would be cache trashing and a
-need to have a lock for each queue. After the scheduling, the requests are
-eligible to be sent to the hardware. One of the possible schedulers to be
-selected is the NONE scheduler, the most straightforward one. It will just
-place requests on whatever software queue the process is running on, without
-any reordering. When the device starts processing requests in the hardware
-queue (a.k.a. run the hardware queue), the software queues mapped to that
-hardware queue will be drained in sequence according to their mapping.
+can read more about Linux's IO schedulers at Documentation/block/index.rst.
+The scheduling happens only between requests in the same queue, so it is not
+possible to merge requests from different queues, otherwise there would be
+cache trashing and a need to have a lock for each queue. After the scheduling,
+the requests are eligible to be sent to the hardware. One of the possible
+schedulers to be selected is the NONE scheduler, the most straightforward one.
+It will just place requests on whatever software queue the process is running
+on, without any reordering. When the device starts processing requests in the
+hardware queue (a.k.a. run the hardware queue), the software queues mapped to
+that hardware queue will be drained in sequence according to their mapping.
 
 Hardware dispatch queues
 ~~~~~~~~~~~~~~~~~~~~~~~~
@@ -143,7 +142,7 @@ Further reading
 
 - `NOOP scheduler <https://en.wikipedia.org/wiki/Noop_scheduler>`_
 
-- `Null block device driver <https://www.kernel.org/doc/html/latest/block/null_blk.html>`_
+- Documentation/block/null_blk.rst
 
 Source code documentation
 =========================
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-6-bagasdotme%40gmail.com.
