Return-Path: <kasan-dev+bncBCJ455VFUALBBMN5YXCQMGQETGUQ5OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19259B3B549
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 10:02:59 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e931cb403dasf2330283276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454577; cv=pass;
        d=google.com; s=arc-20240605;
        b=HQ/8Cg5JqC0y6G7fR5F5aBQ3C5K2ZA1i/hrIw2Z+OBlbZwDBVNo81ddKATXutxq4HD
         8prgbzGSkDiDdvp/w6RrVZzDoL4wf24Ugdr7ObM/+hsMdiyGK7rHa5MdwEPxNg6VtEXh
         ud6p/eM3qNnsWg3Rm6+2pz7o43vw0ADqzonm8gnFJFh0/lKSE1A4k6QQWXavXxrPs5eQ
         Bu7WJT9EVNR68u3jgUvhcsWkIDYNQZyuuv3JwzK+BoUA6tY2Br2opTqlFw5lu/3RCyEP
         krL1Y0jYxdKrXHP7FFIm74vdvzRTnbx4D+DR2dSd/z+6qTASYLHSjjTZO//he+MxDGHP
         c5jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ul+ZUZ1DEZLRbrsbeejYdGLGoRtGQjcEhngJ8OOFjyA=;
        fh=25k/yNykHGqOlcCJdiV363B2WjiiPDqzZyVBIdhR8kI=;
        b=A//+DJHgDl+mr+QFM4vthocZTQM0o3xFS1nhY3jqLrkMQNPrK2UtpzCHjZhiJ5J8oy
         Ma/dFdvODg55tR/OzdlkkIZ+koHyfDIyEFGVyTR8zpW6As73uhIzsEMZ0JIKySeT7pUO
         zNjzEfHWX6mRsY8tajzQV+n0sO++M1F4jHKgr1eqcyY0QXOiXJiJNk9gPMAvGyZPqW+w
         i2TPhwdnrkFz/FfXAHXTBLzcvzV59VJi1S10Srst5j7RdgUWY2VS+K1TrbzYh7LxGmFT
         PYQwRORAN2iIkvnzyiX+ZgJR9LIcQSiHgeGJAtQdH3Rr4AlnQuSPd/DBHdLmrePsAy0o
         FlzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HdX5EHHB;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454577; x=1757059377; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ul+ZUZ1DEZLRbrsbeejYdGLGoRtGQjcEhngJ8OOFjyA=;
        b=IqLc8drG1VnhjXKkHa57yqA+h+EcIHgtyrnSSyhuW5EcKgpsluB1rkw+OAgTV6f1wf
         bWVu2lA8YsR+Krwz6wUCTbgaqxZtb2O+Fe6WRWsaGozK8k1VPRuskhY4vuBPaTFntRWH
         AFpGef14+CwAZWBQRDQAc/vQ8n2F4E9BJDvJi+5i5S7Z+D1U5OyX5ugb6fcKjPFX6GPH
         Y7q585bIiWRdjqo5QU4Ei3hOil1HYonue33FSvlKujM+5pduCdmM4OpB+ZQ+KL2DLvPj
         iWg45ZL7sF0x2CcSTuaL0Q5NFZh0H+AAwvXiioQAo+gL5K7d1c+OTgdWEE7vCYyEc1Pw
         MFtg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454577; x=1757059377; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ul+ZUZ1DEZLRbrsbeejYdGLGoRtGQjcEhngJ8OOFjyA=;
        b=GT8rZhK6XiKRyI33ojrntvXQ4IPcaQhLcDD58RZNmv6jWNDkZkhqBVDLEcjKVpTupM
         4Fgu0UyyRtT+cHs55dCEvnUjQ6TCdKv+c9HGOS/KO0OA4X1H+6H8k7ZeMwDDjM1ztgZs
         qCcTMK3fnt/ElHN+UbWuVr7g3KeZfvsPa/mDlvK9gJZ2I1XlOnRCWo5vABhU1rTPsw4U
         qJD5bRoigyM+0BmgyX1IaHluqI9zJXKYg1EASRSwZY6ryC53ObZvEWgNbQlfDaXedhgS
         8htm/6L6ZI9Qse/KhubzUr0AnxJRDZMobvPT8yXt8h7/AwubJLE3SHmFuo7V97g9yBDW
         joFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454577; x=1757059377;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ul+ZUZ1DEZLRbrsbeejYdGLGoRtGQjcEhngJ8OOFjyA=;
        b=in8JrPRTfIMFjejdJb4m/xUT3LKjB/KxZENo+tzkahk5VtQqf4m5k/F8c9xTEcnPKZ
         Qh/3rlaXrpUAS5cM402xHzpxUITTxeKTUPmNHkgda/wQa1cXn97PX5ojnYQsg1pcPh5n
         FtgpDw23SuwjuAP5cNATVfg5AwJSvtDCeVGCmxOJRMcQaHvcpmbDnwp+yKT/b0Iio5un
         MbyqzaIxFtcuYg9I2t/i+/QBg8cjKViCM6WoE4N8Y2+Zg4IlV/fkc4kvlUGG5Kmg4Iqy
         PhOWzOGJHVCzJypFIx7bs9WiHgC6i4kDccfC/UIDoDOyxMbTQBUc9YgW1WcN4WHYhiz5
         aX2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8bzP9bBEmlcFkKW4z2ICfv0NsrfZb3O/Kl+4ZM3XB9gJhaCyC6BAZBHXwbROLBwWiICehyA==@lfdr.de
X-Gm-Message-State: AOJu0Yy4t525eRyOIRBh4bZAQuzb+2y4TS/4f80QpsI1iryawA74veGD
	zcje0oHZ1h3XSlTphOK2zzt8fjpSjfR+nSZEyk4D1QBcrFK5NusKGO7j
X-Google-Smtp-Source: AGHT+IFWrabwZI6eYX6IsaI0/fe59CIs35lt2+umn7lrIcwahqJjuw+iluP4NB3ouU0SU1+LACxXsw==
X-Received: by 2002:a05:6902:1205:b0:e97:21e:5d99 with SMTP id 3f1490d57ef6-e97021e633fmr4958536276.29.1756454577339;
        Fri, 29 Aug 2025 01:02:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeU8/hJzRGaZBHlsMWqD4YOgrziMqe97sE1m4S+q8YcFA==
Received: by 2002:a05:6902:1706:b0:e96:ea30:d8cf with SMTP id
 3f1490d57ef6-e9700a8bfc8ls1677803276.0.-pod-prod-06-us; Fri, 29 Aug 2025
 01:02:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6V8hc1K+pQJJ3AoWhU6nuE5DFEQbeQm8D6l8Eie1oCJ5Cqn5xrkrBGkzxZVARJOWHlO0rs3qMX2c=@googlegroups.com
X-Received: by 2002:a05:6902:2a42:b0:e8b:bf29:866c with SMTP id 3f1490d57ef6-e951c3cc3f5mr28588837276.27.1756454576125;
        Fri, 29 Aug 2025 01:02:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454576; cv=none;
        d=google.com; s=arc-20240605;
        b=jh3q6bsfvMbfwc5KBFRHkoGyr2nHNG1kgm3Gcy55Iwnm7wufftSFu1LQmljujFosG9
         ltDg/SRW8nmqDUNbtIE06wTk6aamHpoKUZSHsHwtxr8Ya47HbisWvJPmyUOB2KQL/6R1
         LXY82qvrU5k7YqyDN5dw+/W+Ou0OWrx07WWLGXQOJmG7xY7gALxZIuvw8qQ7eBHsGwRy
         8Ts2GylAqy+AIlVx7QIYYuaSgU0dteMKTjpOIQLCfHWOaWLWT8Osx6V6TB/1r7vGCYw5
         hEIaas5m3dbYUGPzpE5HogQRBqALOJRJcCF0LxnMnWPXq9nkoqKSnsYHTNKT0uE8U6wd
         3Wqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mQcUO3MMNiHKjyp0GXG4A4uvsTQgAsYSLBA8ucpISkE=;
        fh=DmZphfZqmWH0z2jFTK3UQxxj2arm86Hlt++cwmg0VwE=;
        b=csE5BeBzKlpNHn2UFl4yjTK49E3HOdeEbKPDn/wcVQvgKaSVj+A1iznkRZWQ4YSsjD
         Y+gIhzCSEFe6yfAxoxqwJNLZG+MqR3f6REbBpsKoi64mOo3lEsvTxhw2hb/8zgZpw6gn
         ZQd8XYRQ9NUxbfZJZ41uV4BfjQtdKlZcGhK/g2tpRytmuAoEjWpVeJfsyPt1kJ3P7fvT
         wPqHBU813nZJOEiOV01N4IxXKOUT4/CIFLNatOLC3DhnvfWOx/ir3j8paIOgseSmY6xG
         4CzVPhE2WWf8idm46rL2SnT2x7fT8KUhyxghZPO46uHJ9p482rJAjWsEryUns6NA5gv0
         FYsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HdX5EHHB;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9849b71852si75835276.3.2025.08.29.01.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 01:02:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-248dc002bbaso13539895ad.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 01:02:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVGQw7BV8MvElFNGQj+belgzEgCXEpHSKReC5bUPXDwFjh0mtkK+vUj+/mlrqrMKWg3Tg76QUrVkM=@googlegroups.com
X-Gm-Gg: ASbGncvTgarylsS/mWWhHPH5dl6W6TYyDVQ5J0tsVM4YnBS7//uaS4gvIgn/r9ppO2i
	aP+RqLCgZPtBgwbtu5u8TpqzJZDx86qrTcf4FOExwt2HfY0r0DgEkmg4QSCaruqyk6Gv1Z4C6CK
	EMUJpmJqhN/H1OKdwLdDPdyIDFFqawiMBlCar064G3HjxdNBQ6rhPp3YumL2vkI9+JA5sjnb8cr
	9hfhR4eeubJRS1m349tHrWsan6sUBMVP5i2fdAGWAWkstrMQmgNSvqiVMhP3GTM79ym3EuqRHgW
	9fpslIsfkm9LN/H4rfYU5kqp/xIXXsudwCo1fn1H/diy/YCdf2nAfkFTHKlY9S4+8nl50gTw3v8
	Kgp/3nWKekML2RolUWAc0FGcT1A==
X-Received: by 2002:a17:903:4b43:b0:248:c5d7:1b94 with SMTP id d9443c01a7336-248c5d71df2mr87990615ad.53.1756454575277;
        Fri, 29 Aug 2025 01:02:55 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2490648d04csm16959215ad.107.2025.08.29.01.02.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 01:02:54 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 3924545A3F85; Fri, 29 Aug 2025 14:55:29 +0700 (WIB)
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
	Linux Kernel Build System <linux-lbuild@vger.kernel.org>,
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
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
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
	Liam Girdwood <lgirdwood@gmail.com>,
	Mark Brown <broonie@kernel.org>,
	Jaroslav Kysela <perex@perex.cz>,
	Takashi Iwai <tiwai@suse.com>,
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>
Subject: [PATCH 13/14] nitro_enclaves: Use internal cross-reference for kernel docs links
Date: Fri, 29 Aug 2025 14:55:23 +0700
Message-ID: <20250829075524.45635-14-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1391; i=bagasdotme@gmail.com; h=from:subject; bh=evrdLEAoXKuQzTljW81Kh3KyWLApG8gUObVzJ2YlNgE=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY16J9usWFB1WvT+NSavLIanh+698vZJvp5Iqyn5cF Oeb1Xiho5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABPJ/8zI8C+tSSfleGvDlW33 Ss5v/Xrog5zFrjCmKzem/Vr2Ka6JL4WRod0y2uaV0GJBfuHrJzY9vTqdTVAvLqhtcdO5S89liyP teAA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HdX5EHHB;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b
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

Convert links to kernel docs pages from external link to internal
cross-references.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/virt/ne_overview.rst | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/Documentation/virt/ne_overview.rst b/Documentation/virt/ne_overview.rst
index 74c2f5919c886e..572105eab452b2 100644
--- a/Documentation/virt/ne_overview.rst
+++ b/Documentation/virt/ne_overview.rst
@@ -91,10 +91,10 @@ running in the primary VM via a poll notification mechanism. Then the user space
 enclave process can exit.
 
 [1] https://aws.amazon.com/ec2/nitro/nitro-enclaves/
-[2] https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html
+[2] Documentation/admin-guide/mm/hugetlbpage.rst
 [3] https://lwn.net/Articles/807108/
-[4] https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
+[4] Documentation/admin-guide/kernel-parameters.rst
 [5] https://man7.org/linux/man-pages/man7/vsock.7.html
-[6] https://www.kernel.org/doc/html/latest/x86/boot.html
-[7] https://www.kernel.org/doc/html/latest/arm64/hugetlbpage.html
-[8] https://www.kernel.org/doc/html/latest/arm64/booting.html
+[6] Documentation/arch/x86/boot.rst
+[7] Documentation/arch/arm64/hugetlbpage.rst
+[8] Documentation/arch/arm64/booting.rst
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-14-bagasdotme%40gmail.com.
