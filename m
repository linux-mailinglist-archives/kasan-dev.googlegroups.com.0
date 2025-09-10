Return-Path: <kasan-dev+bncBCJ455VFUALBB6GLQPDAMGQEW2ZBGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 99CD4B50B4B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:09 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b5fbf0388esf56977681cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472248; cv=pass;
        d=google.com; s=arc-20240605;
        b=SXH50vnZ5rFwQP307YP2vgChtLT+Q6/LImbJsFYNXDtD1SkUOagtErL0EcHBByXvfP
         /cPMTr2UYDgH/VyPRzBeXfLHW1rLp8SrBP0yYUasPLwK1nYWtG2C4HiRuVvd0gMb8qFl
         PB+wzoz+jo60xkas1EmNh3+Ou37erkuKVHIw6Vm5nDumpgmq7DxeePqp9pfUOuNN9k9W
         +Qw53pDzSgpNexP7vItVF1Sp/gds3MlHHb9f9Y4ElmbJmHVbgZEEdtuPNuwv1I1yJgHY
         3Tbhe/cp6F2ourpRjtMhPF8oDVg15aJonaQIwDh2WBZTLdZzBfIkSykLaCTp4uBUqCl+
         /noQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=4Oj/xNQs8bINsYOJOXaGySAhCNCtZqEdPh4MtuFWZnI=;
        fh=cxTyzqOz3SNmeK51NHQOvqzgr5m2MSQIRVK7YxrGNcc=;
        b=ApxHbVLWw3T5CmGIVu0jmlje4kyKa3ub+Ebwz+uDnmzyJqrEdQKHyE477TeKZazSlc
         tGEk1SRbeK9rWEQLv8j2W53tNZcxw3wjyHoyTslpudgct0JXSOB0ewUqrSU3Clu3f6Bn
         d6nsxolvBAVbrH7LtMMWb8RhrZLVfcgV+ptpl5p/zqSG7fXPgzWwx0PF+2zfkjj83b3i
         rU8CsN8fNuLU7xbMiIyhfq/lLUynkm1Uw6rlk+BfOPVfkexQkM2Hg4wWUpv01m70HE1I
         bk+IXaxO6Wf9MJiSZZXZvjN/RFHEDS7gyhhd70euG6Fa6VIw5nplm2TTJHbewsrGXM40
         3pLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WxYN2Bt1;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472248; x=1758077048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Oj/xNQs8bINsYOJOXaGySAhCNCtZqEdPh4MtuFWZnI=;
        b=v6OG0mwkCw+gVWTyXnKDlCWkR5pJ0hyqNg+2h58lktZxtM0k2YIM02XE7ZWKtTpcN4
         bl4wXp9ZvvgHdM3ZOOSCH/1Rl5BQSrQ7RXSWN6qV9nzpPWY+23yHtfzZ/1ykQtBHsb5U
         N1bbOUwAdQf60Ad67gCF03pOlUdoKNC+X8qvnAtAFCwpbkjs/VlLQlW8/dGdHrNktXGe
         bOXi6ovlM6TIlq575Z6nP9gYsS8+ZjjvpheUYuEXY20PNoncyNwKYyPZHEZ8o1Xe3S5f
         XcmpPlwNFUaVzhc7bnwCtUNZy+Qf65T8pCi8FWvyaLotjoJU82awwT3jfNjQ4B59IlKI
         Xkyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472248; x=1758077048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=4Oj/xNQs8bINsYOJOXaGySAhCNCtZqEdPh4MtuFWZnI=;
        b=hWv7mvLRCqN3poYKAFaoIstcd4HZmMcIXODm4EEPYGZhCcFWnrkviQROLz+vkU3KZM
         hziyrVP2UdYzXxOf6vCcNqCsOBocqRWkP9AMTLZ8zCYxJUh+WSnVQHq4pHRKrbnlQS66
         TC7Khm/A1WYLTcWq4MZQx8cSiCRuTOcBUIiu6x38ZE0xjuCLzCuMko2kAq4PIBEhp7LL
         QDbS02JFj7MGQPhqiQaDG7DZ+jnM7R2mv1HLD0tZlD3nLw08gL/8BfHkLMfxleamVHFR
         ARG1J4oYKIjTYIGa+PI5xOk8c5iNTniQSmRAT4cRqs3X8PyygfxUpMrSOKvYdetr3eY0
         ffrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472248; x=1758077048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4Oj/xNQs8bINsYOJOXaGySAhCNCtZqEdPh4MtuFWZnI=;
        b=v8NFicfsDLHhyxthZUyRG2FYTXQMiQm46Wey3MgjzPiHPDbUVQM1f0A8qnymZ1YWPT
         9rTqvZF7/maASJwjO4KQjFQCn1WmEfk8shPorKxXg//gCxlS5JnMp4IdvoRdb6Dz689u
         ppwV9wbgDg0edAY55k3855DXFjobLXH5P1LVYAYFIr73F5VnQYnKzeDjMGfbvbFo+LAq
         YkeKfGnceGhf4q8WrQI1j8/VyEQP7khXF98EaP2Ouy7LaEuPQL/xDvoZ85ydqVrEwLpE
         7SuKLSn4oyr5DLR4CCoJFQYXzFiMo6yFu1Hp1b/M1FbrAiUyRGd7zxXnMxM5sHvLIoJj
         Xtkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0uGL941wHfX+gtIFp0fJa2BJnZq7I5jg55jqqXnwteXhNlAH5LQHCObdIBvisagNliv4xtw==@lfdr.de
X-Gm-Message-State: AOJu0Ywmaor+1bOqff/KxjRwyOmVuIyVXT53eCWLXHrMQyXeDB2O0ngm
	Ypv1W3kuo2Yc/BveHEQMzikJIj/iOhDntwxAeT4Ww4qb1sEiP0xH5tQZ
X-Google-Smtp-Source: AGHT+IH8nUS/LasuceUY93NItE6sotKpPv3qcW4EctQTagjX0NekI0fuOq+b9Je523xShkH6OL9czw==
X-Received: by 2002:a05:6214:2aac:b0:70d:f64e:d496 with SMTP id 6a1803df08f44-73921b39bffmr145179026d6.2.1757472248436;
        Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5XfWEvIJ8wlT7hhCO4OmsWM3UBDNPfnnK58b4lT4n7fw==
Received: by 2002:a05:6214:ac8:b0:70d:9340:3384 with SMTP id
 6a1803df08f44-72d3c1289bals71801696d6.2.-pod-prod-08-us; Tue, 09 Sep 2025
 19:44:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLUTPjm8BnakbBJc0fmARXL7Y8auFLAYREOvwtWusrxmC9X7QKNRJxbASby8uetPfTRED/w4CGCyU=@googlegroups.com
X-Received: by 2002:a05:6214:2267:b0:742:90e:d904 with SMTP id 6a1803df08f44-742090edf3dmr147110326d6.50.1757472247062;
        Tue, 09 Sep 2025 19:44:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472247; cv=none;
        d=google.com; s=arc-20240605;
        b=RNrNakcbrfhzL+QyNweTdm2m1Bg7Ycad8EQ3O5Q5mF1FFmrb3+Iz/oApnB4f2+YOv8
         R/7kv7hBxCqu9Jqfal3AKI4v/vYVADVOSKvIdJuVER1+22sXeo+Y7EqcfhWlUq8hNmYd
         33nwf9Kqo5haXMDJUNa8lhmb1JDzA5i7M/jis9Z74bqiK8igg4/dsIMSAAnlUEov+2Sv
         w0jTxUfkmUM+vLmdbHnHhIuT5dXka70iq3k0/mzty4HKpZt5ho5V/Y5N05hNhNwFeru4
         IIiW2AyAlVfSk7/hSCvzx3pBHzn8A56ZDPZJ8aTjdjNXBrV0hB1/hhf9OC176tndOYle
         DLdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fK0hEDM5Yyao3a7xqBzpr49p9H5HB+om5vfXDIKLdeg=;
        fh=pyVfG1p74Y3gvalr2Ir2+ulQpztb3hO9GNjBwTsSXfQ=;
        b=jIbdL0p9wSQ7IHwFXgnESd9GLgNW8J5+s+lFtE32pw1X5Ucy1ROkHGSOJU9IAMSLjB
         DnCLF6jnaYgbIV34bQ4Dzn6A8LspPcXppG2rNmPdDjTjO2YIRdcaBOLkKA2dRaidkQF5
         3//xd3SjS0Ae4ah8qXuNEqI414fAQZeRtfq8bU/pUC12xky1O/Vh8H4TQxx7O2GD88cZ
         heFSmN7BqCwGg1c92reAsEPg3B+622UDDiAm3xrYuyh4QbLlFgN/4czHlkgRowRnpmsl
         /0/gzQwlQoAg6CxNGVs5sp0jHBTysKTKxPViIfG+xSNuHYlGXfJ7cMUpMWxiJ2bEVaOc
         iy9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WxYN2Bt1;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b23a4713si7370976d6.5.2025.09.09.19.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-32d3e17d927so4158940a91.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVha50Rz7fVSqDsuX/r5MxovAqIIRFcWaPDx0iQn4he+CjTmDFpYl98HZnm1Ys3C4Gkh5q1movEFh4=@googlegroups.com
X-Gm-Gg: ASbGnctmNCHsHVioJsFgMAsclna+QmSZcn8n+nhe/1c3g4juVEmaieMGdAK6SHoTuhA
	pm8x8tmqjNX4M+BuIcSr+Ltwk445qVz0EtcAF6Gi4o9Osg6CsUrFGqod8iAykT52HFzth9H6Tcs
	BY7/SM5cNiZjDiQaQe59FbZv1iIhUt7cztLQpXUWfHTs/e88ToLwSPd3n+R9PezzxCCsTV6+MNO
	nIjpOH7ZV+Ni2B1CeWRkl5VlryAXKLZbGDJLKRfuG+3f5eaCG/Azax8odpARCLcJSMW5E+tvJvI
	9wAxkCTKoRQLrIIfMOCtbYOj0e+gvcfuJVBtXCe5GTOahnYDRhita3gDPjDqyvkVQqMptj13Idg
	k8c/DlJa0O+15exsk5OJePqfxWQ==
X-Received: by 2002:a17:90b:3c90:b0:32b:8b8d:c2af with SMTP id 98e67ed59e1d1-32d43f0a76cmr19148626a91.9.1757472246443;
        Tue, 09 Sep 2025 19:44:06 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-774662f17a5sm3518975b3a.92.2025.09.09.19.43.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id C367141BEA9F; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
Subject: [PATCH v2 09/13] Documentation: filesystems: Fix stale reference to device-mapper docs
Date: Wed, 10 Sep 2025 09:43:24 +0700
Message-ID: <20250910024328.17911-10-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2828; i=bagasdotme@gmail.com; h=from:subject; bh=Ip9RCWVx3N2eFboDnh1dVntKjUKs5RT6sbpEBdmz23c=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHniixbj++M2M+e9AK28XZP75VaZfxL/rvM//ttckLa 3oE7/o/6yhlYRDjYpAVU2SZlMjXdHqXkciF9rWOMHNYmUCGMHBxCsBNZmb4p1i8uPKB8ZP13wum BPvKxR5SWdltK/h88a0CIW7J/3IPcxkZtk3KCLwZnfbq4QUbicP9bC8vlyYEbns3a5pPVM71i2f ecgIA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WxYN2Bt1;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c
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

Commit 6cf2a73cb2bc42 ("docs: device-mapper: move it to the admin-guide")
moves device mapper docs to Documentation/admin-guide, but left
references (which happen to be external ones) behind, hence 404 when
clicking them.

Fix the references while also converting them to internal ones.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/filesystems/fsverity.rst             | 11 +++++------
 Documentation/filesystems/ubifs-authentication.rst |  4 ++--
 2 files changed, 7 insertions(+), 8 deletions(-)

diff --git a/Documentation/filesystems/fsverity.rst b/Documentation/filesystems/fsverity.rst
index 412cf11e329852..54378a3926de7b 100644
--- a/Documentation/filesystems/fsverity.rst
+++ b/Documentation/filesystems/fsverity.rst
@@ -15,12 +15,11 @@ of read-only files.  Currently, it is supported by the ext4, f2fs, and
 btrfs filesystems.  Like fscrypt, not too much filesystem-specific
 code is needed to support fs-verity.
 
-fs-verity is similar to `dm-verity
-<https://www.kernel.org/doc/Documentation/admin-guide/device-mapper/verity.rst>`_
-but works on files rather than block devices.  On regular files on
-filesystems supporting fs-verity, userspace can execute an ioctl that
-causes the filesystem to build a Merkle tree for the file and persist
-it to a filesystem-specific location associated with the file.
+fs-verity is similar to :doc:`dm-verity
+</admin-guide/device-mapper/verity>` but works on files rather than block
+devices.  On regular files on filesystems supporting fs-verity, userspace can
+execute an ioctl that causes the filesystem to build a Merkle tree for the file
+and persist it to a filesystem-specific location associated with the file.
 
 After this, the file is made readonly, and all reads from the file are
 automatically verified against the file's Merkle tree.  Reads of any
diff --git a/Documentation/filesystems/ubifs-authentication.rst b/Documentation/filesystems/ubifs-authentication.rst
index 106bb9c056f611..9fcad59820915d 100644
--- a/Documentation/filesystems/ubifs-authentication.rst
+++ b/Documentation/filesystems/ubifs-authentication.rst
@@ -439,9 +439,9 @@ References
 
 [DMC-CBC-ATTACK]     https://www.jakoblell.com/blog/2013/12/22/practical-malleability-attack-against-cbc-encrypted-luks-partitions/
 
-[DM-INTEGRITY]       https://www.kernel.org/doc/Documentation/device-mapper/dm-integrity.rst
+[DM-INTEGRITY]       Documentation/admin-guide/device-mapper/dm-integrity.rst
 
-[DM-VERITY]          https://www.kernel.org/doc/Documentation/device-mapper/verity.rst
+[DM-VERITY]          Documentation/admin-guide/device-mapper/verity.rst
 
 [FSCRYPT-POLICY2]    https://lore.kernel.org/r/20171023214058.128121-1-ebiggers3@gmail.com/
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-10-bagasdotme%40gmail.com.
