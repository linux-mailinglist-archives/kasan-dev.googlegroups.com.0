Return-Path: <kasan-dev+bncBCJ455VFUALBBTWPQPDAMGQEMVUDA2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id BAFF5B50BD5
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:52:00 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-b52358ededbsf205940a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:52:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472719; cv=pass;
        d=google.com; s=arc-20240605;
        b=DeUs3SEn388LrwQIzSLCe5dffZu1VJwKKeQrVACbcbmO6KQTR8DBBWgqN2x8U808AO
         W2mS2DMums6jef5EPIE+Z2HWc+WRkppgpC+aQw4h+tjSFFMYjoh0he46sKXfE0GQpssr
         fcqAD072f+132S33zzIOCGJU0/xuzm/ynM/vrcUB0GH5jtNZiNXUkPpEdvN0wyUEvhpe
         xEtm1/RY5T82o3As5jAFFtQ9CW0E+RJP/j+piBTnnHTDWahaAOw5nwcHCPiNZ3xdiNIF
         CubRrRD3OLDi2hqghclNpYK5KrlZY3c8V/d92DBLUUQxPd1fGyyU+qalKSb+6ruyl1IX
         Kxlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lv98mIFVBgIF9tBJfYedRXqYU++f68umoNaYSDNpG6k=;
        fh=i7zk9G5EMJTJac7HwAoyxbEgXiO52FcNChiFUeGOfI0=;
        b=AGPL0niFHUBUJQab3Knkat4tf5vThXf3nw0fpOuUthyC7QvmOIjNU1ivd+IT38Igay
         zQDTDrSZBkRjeu/CBqUshz/HKKc1ZKSze/hRQZuKe6MSU9OkMr5ZGDe7J2HjKmPSc7bA
         OTA0zYOn0mZsdO+33G3eQE1Hc4+w07oPn3BadYWPZRVV7lJgdOKQprmK1Twwg/zL2U2T
         jp9YVXtP8FYudzOKJEJE3112Xt1HbLoEmMQ67jLTdhRqrvbVxNk+jHHXypk4ai95cwKR
         IdzQEsULOzdXOkPjrQaMF7Q0AOOxJT4YbqkOaYQOV/LXPOQAJLMpYt49wwp0ilS0d62e
         2Svg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DVWI0RVM;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472719; x=1758077519; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lv98mIFVBgIF9tBJfYedRXqYU++f68umoNaYSDNpG6k=;
        b=PA26pCIWxu0RBPVTRNXbsb5BzSTmr+ClryfhIIA9bVKU6TlIZOEaEwjojiAhCIQs/h
         rGa49UoRXzwZiIGMjwUPpLEXMyEpeUQya7N6zY5t5LWW+LOZyJ1TNDcXOagmKk/6OJRt
         dni5R8QOLdgPUhbybWGIXcwpKqZc7qd9SRBATmxLZgLMFEd+lPPgUOcTjhUX3oTlALrP
         BeaCTXvNeFDOSCTiCYWa9++oiCCw+w4/0n0g6ocVE6Kij8Flp416tTvBnxnKRIAjt0lr
         QYUIGRy0qYucIozMXXRhI+pYjl0G19bjv51QUvi4E1jH+kRE8K9i1Zjl8bx23v2mWC5q
         urug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472719; x=1758077519; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=lv98mIFVBgIF9tBJfYedRXqYU++f68umoNaYSDNpG6k=;
        b=aOdvNlS2REShJCbcoUaeXDQLPm8iQy0TfjDBFst1CoqHKfo2OmLArN+ThgSFlHRyA9
         8ly/W3fo+/X8zb7W8KcjnQGjzPqaR1ZbH6YIZ+j1gVlAbwsus+GDw13T6qotPmEbjsds
         VhMXAmKjRaca5RSPIVYyOIb2v2Y4YpEYiITceQyaXTfM6635Z3rPdfFBownQ333JYJ64
         R7XtKAy36v3LKzTZfmTr/KSzqZaPALLVCYDuckxosdezXhd+QPVNGQ5mDkK6DXjwPmBO
         Bs9CouIg0/Kj7GzMS8rW9xoCdrMUOYMRHcizNLuKnl7ud+42DX67xTuBV0ecUJ7MgEH7
         xiYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472719; x=1758077519;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lv98mIFVBgIF9tBJfYedRXqYU++f68umoNaYSDNpG6k=;
        b=ptG5RIX38GxunvGq3ZIQ+W06kQSw0uxWCecwa2kdA3TM0PJGeQ9aF3pucXqtqeRl0w
         Dlrbxu60+ooodh5/cRUXA2vK3Uko0x5IMmMVWVnpEmiPzz5ROhtupptPAUjpfNnV8GS7
         n5lBcLDUeo8qYKDc6p48ao7JKqEVtCKoZRmjPCQevZX2wSD9hkwa6u6zTJVJc9CAojMu
         a4YMmWDV573YsAvhp/oabf5Ui0M8v30glCR9BR5uP9Ric9ma6qJdcyFnCVYVOqzF73P2
         af+F0++NCPNYtIski08vmKa4oz/1Vo14LlN3a4U4wuAuS/3rvKYmeRKBg1T4G7f04nw8
         Zl4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9ecaR8jDceYMXmqHv2i7+2VN/Y9WlqjFkO+E1FIwHhf5Pxc22DQihQ0qosRMvosTGpU+GTA==@lfdr.de
X-Gm-Message-State: AOJu0Yz+i25ol66o6OMno94J7cyZ5Ui2SCwHDU8ajkcXumx8FW7p3bbJ
	VoKihp871lAD+tLRzJ5huOBmFjwfMTZmcpj3TX/FpCpBMDurJW7lYuQt
X-Google-Smtp-Source: AGHT+IEKxdeKdNfLDvX5ybZtBlVDyIxsCI7eYXObS4hd9EzG+JRwoR3VHWHM+Jpkf9YgL4FgYq+6LA==
X-Received: by 2002:a05:6a21:9989:b0:245:fb85:ef6a with SMTP id adf61e73a8af0-25376387ee3mr17421745637.1.1757472718660;
        Tue, 09 Sep 2025 19:51:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc94G3x06ceqdHoO5WFu6XKQqzWPHX9bMerepsWKLbtLQ==
Received: by 2002:a05:6a00:f0b:b0:772:5448:94c9 with SMTP id
 d2e1a72fcca58-775f610d5a9ls221345b3a.2.-pod-prod-00-us; Tue, 09 Sep 2025
 19:51:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfmeivJkVPUzwP+nvbJQKf7IQHdwY0sZRFZO7yRScz8fJqyIYRRhUr1gIjmuPo4/tOzGLJ74Gp0o8=@googlegroups.com
X-Received: by 2002:a05:6a00:4c99:b0:76b:f7da:2704 with SMTP id d2e1a72fcca58-7741bf3f8a4mr22462095b3a.11.1757472715984;
        Tue, 09 Sep 2025 19:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472715; cv=none;
        d=google.com; s=arc-20240605;
        b=eOhoWA30CdsNJGDVOEoFW+0XxEA8ARQYjSyktec+cm2NL1WVPKjJ7VM/aANAPF44Dk
         9KRMB54NHnCftxNshjjn1QscVBDxWY07lxegdNSXRIll++zSpfDGbgCgZtP7WplobuX5
         0AyUC0rbQNoBMLEQDTYL1+Hd/cmsNliAmHNqCKHBf+ZkD8ndjxNcjlmffmxZDTHDC2pq
         BfDBYcmSlGaASZV9l31akdJNPWodVQK+o/VfQxiij4lXWzpgrzRZNwlyFODNl57ce7hN
         mbRK1Cldym3heBY4t7HYQNKJ+j4weVrzmV1yAJv3Kb7C8XVbm8c9eZ8MfXvXQwISXKLp
         Wspw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e2TiZwTLryn0Z2XdO8OaBNvuenSuTUZNT9oHE0TAuq4=;
        fh=15ewXamJ5zCP9kkZECC76Hmx13GVr97ZKYcaYXLNtU4=;
        b=RXTlrbKzfPJoV+ODD8X0OdJt6yE9AJ57rQxlWac1QfWqqlhUCqDVLwF8O++NZUQ6qD
         7djDf1kO+qI6P0tPknn0OJhAoiUAgZ5PHpF3jxJeUb54g3nVjQBNpPxlGpCs/Q9Dt3Yu
         GGY7u1x9DnIpZl0AkU9XtMFlZBMvTSMZrSZWw0PPSf8kTzSOGaqAGkEB8m9/DQJXc3Hb
         pOOeuU2erpMq1XxKlyCR/FVPGqHtbVt/+bU1VWRIFqe69PS6xdft5hJddIpypSvAL+w6
         iMRNPYOFdOZfa/NeoCCoUE4dIYJe9s8OWZHytSmSqfEts6kzyW5wPy8s+RxwY6IxYwD0
         Cd0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DVWI0RVM;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7722a4902b1si1194800b3a.6.2025.09.09.19.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:51:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-7728a8862ccso187999b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:51:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUc9DHub6HUbZuLsJGQSj74hriuIyJf11dqUww2i49+rB9wU1FunV2WKfcAxTzhebaOaoae/IaJYPU=@googlegroups.com
X-Gm-Gg: ASbGncu898znZzbMyoYe1E8fJeMthdx3wgHcGRrSncs/78yXb+qcnd4reXCLxfj89dm
	jf6J+uOh9bv4epFBBjosRgFQjmYkoWJ1WA3KIJ1RSJFeJUSYwHMYGh+7VrknljtbUVKxcbS0lET
	PUEZPo4fs/1SxK+oAFdzzMTAIh+fOjP0cf4F4pQeArNFnX9CLxJjCHcTIsVgalEJP4TKMtWyV9u
	1WJKwMbgVGABocGND3eizXsaVJuIxfgM7q618QMoaQ1gQagPa9qssbqH70N5Oulkytw8Zcerpxn
	5sWknOseyKt7cyVngQHZ4C60Bs1Uh8bxdBcEJlZugBmcadPn84/9xuCgL8w4XGk2o++6i80w09W
	nCEHRGrYULEBblw8qqiNpPkuzNw==
X-Received: by 2002:a05:6a21:9989:b0:245:fb85:ef6a with SMTP id adf61e73a8af0-25376387ee3mr17421555637.1.1757472715353;
        Tue, 09 Sep 2025 19:51:55 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32dbb314b19sm642003a91.9.2025.09.09.19.51.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:51:55 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id F395041BDD47; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
Subject: [PATCH v2 11/13] Documentation: net: Convert external kernel networking docs
Date: Wed, 10 Sep 2025 09:43:26 +0700
Message-ID: <20250910024328.17911-12-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4165; i=bagasdotme@gmail.com; h=from:subject; bh=3KTOccWMzr8DxZPfBNk641Us82FbHT4BEw3lrJOsNTs=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHniglPN1/l+G0b3W08+an+40OlbWa5hi83XTh+GX/4 C8C1xeFdZSyMIhxMciKKbJMSuRrOr3LSORC+1pHmDmsTCBDGLg4BWAiBZEM/4u927OPq/vretv+ eb/f6YB5Kk/Laj31K1IKboVhiko7uxj+pxYZGDy7rZrM+OWh+Y5vk3hP+ti0xKVJLGg67/x7TvV +PgA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DVWI0RVM;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::432
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

Convert cross-references to kernel networking docs that use external
links into internal ones.

Reviewed-by: Arthur Kiyanovski <akiyano@amazon.com> # ena driver
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 .../device_drivers/can/ctu/ctucanfd-driver.rst       |  3 +--
 .../device_drivers/ethernet/amazon/ena.rst           |  4 ++--
 Documentation/networking/ethtool-netlink.rst         |  3 +--
 Documentation/networking/snmp_counter.rst            | 12 +++++-------
 4 files changed, 9 insertions(+), 13 deletions(-)

diff --git a/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst b/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst
index 1661d13174d5b8..4f9f36414333fd 100644
--- a/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst
+++ b/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst
@@ -40,8 +40,7 @@ About SocketCAN
 SocketCAN is a standard common interface for CAN devices in the Linux
 kernel. As the name suggests, the bus is accessed via sockets, similarly
 to common network devices. The reasoning behind this is in depth
-described in `Linux SocketCAN <https://www.kernel.org/doc/html/latest/networking/can.html>`_.
-In short, it offers a
+described in Documentation/networking/can.rst. In short, it offers a
 natural way to implement and work with higher layer protocols over CAN,
 in the same way as, e.g., UDP/IP over Ethernet.
 
diff --git a/Documentation/networking/device_drivers/ethernet/amazon/ena.rst b/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
index 14784a0a6a8a10..b7b314de857b01 100644
--- a/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
+++ b/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
@@ -366,9 +366,9 @@ RSS
 
 DEVLINK SUPPORT
 ===============
-.. _`devlink`: https://www.kernel.org/doc/html/latest/networking/devlink/index.html
 
-`devlink`_ supports reloading the driver and initiating re-negotiation with the ENA device
+:doc:`devlink </networking/devlink/index>` supports reloading the driver and
+initiating re-negotiation with the ENA device
 
 .. code-block:: shell
 
diff --git a/Documentation/networking/ethtool-netlink.rst b/Documentation/networking/ethtool-netlink.rst
index ab20c644af2485..3445b575cb5d39 100644
--- a/Documentation/networking/ethtool-netlink.rst
+++ b/Documentation/networking/ethtool-netlink.rst
@@ -1100,8 +1100,7 @@ This feature is mainly of interest for specific USB devices which does not cope
 well with frequent small-sized URBs transmissions.
 
 ``ETHTOOL_A_COALESCE_RX_PROFILE`` and ``ETHTOOL_A_COALESCE_TX_PROFILE`` refer
-to DIM parameters, see `Generic Network Dynamic Interrupt Moderation (Net DIM)
-<https://www.kernel.org/doc/Documentation/networking/net_dim.rst>`_.
+to DIM parameters, see Documentation/networking/net_dim.rst.
 
 COALESCE_SET
 ============
diff --git a/Documentation/networking/snmp_counter.rst b/Documentation/networking/snmp_counter.rst
index ff1e6a8ffe2164..c51d6ca9eff2c7 100644
--- a/Documentation/networking/snmp_counter.rst
+++ b/Documentation/networking/snmp_counter.rst
@@ -782,13 +782,11 @@ TCP ACK skip
 ============
 In some scenarios, kernel would avoid sending duplicate ACKs too
 frequently. Please find more details in the tcp_invalid_ratelimit
-section of the `sysctl document`_. When kernel decides to skip an ACK
-due to tcp_invalid_ratelimit, kernel would update one of below
-counters to indicate the ACK is skipped in which scenario. The ACK
-would only be skipped if the received packet is either a SYN packet or
-it has no data.
-
-.. _sysctl document: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.rst
+section of the Documentation/networking/ip-sysctl.rst. When kernel
+decides to skip an ACK due to tcp_invalid_ratelimit, kernel would
+update one of below counters to indicate the ACK is skipped in
+which scenario. The ACK would only be skipped if the received
+packet is either a SYN packet or it has no data.
 
 * TcpExtTCPACKSkippedSynRecv
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-12-bagasdotme%40gmail.com.
