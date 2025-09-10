Return-Path: <kasan-dev+bncBCJ455VFUALBB3GLQPDAMGQEET3HJAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id A534BB50B38
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:43:58 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30cce8f9e59sf8357076fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472237; cv=pass;
        d=google.com; s=arc-20240605;
        b=WHNOngCf3gt+3yh1YS3H/11TWegL6e0xLdFzIduQRpt8Cf2HT+xGxcHULwd+ROb14w
         4MaKmt1a/xD5QOpVU/f9y14U0NNDVDJF3X3e2yUW6q8IZwUM+z/MuQFdKnTEuJH1PL5D
         cCvui8qPRAAHdXc1qy6iJ/Je9rw8hP4ZWFSjxzTl9PpeQISSHlQEfFEtR76c/VM4fkQk
         qnox/d0OIsxGqX6nlT20sis/Q8u38QRKNDxrxFERUFy3SjacmlOnp294KINeb4gIubEO
         xigz3h5LS//Xbf4SLDbl+UZNvByTkBOY7MCcHR1Smy+w3LFDBqOcHulbBrtOlTHmRIFZ
         4PIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=ZvRTvSqxwREU5qD37D6rehmhARia0z2On/CaI5GiCSY=;
        fh=B/i3XHfccb8k5+RMC+96HpScOKX7mkkn8koBMYIiAkw=;
        b=Yu7kSuYbqUKjtTlHlmENx0DEQWr3TrFOba0XU4c8QvHSE5U/659e+bsVc6t5o4EQnh
         diQz/kL67SEj1LlOggdoyJ2YNSFT3r54yCYDvBRCKt8FrUWgEX+xGA03CgQtOOrPr2O9
         aylEqGom+ASxZQ0RaGXt+kFUTZhLU0TRCsSRbSZkIxYXIwsVIAWd4vAY6AAx1d7iimsL
         FtH1oKVs6RDONEZ0v9qaOzN5ZPKAmjGQgKK6eEahd2shmPwc5jZr+f+XVNLfe/DmWJyE
         JZwizGufhGVd2vkTePsdzH1CCZL6QvNIOEB3Suu8tWPRPF/ujhhBUq7etdqZtPyj8klB
         x5AA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EFaK4Eb2;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472237; x=1758077037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZvRTvSqxwREU5qD37D6rehmhARia0z2On/CaI5GiCSY=;
        b=HTJqK3JiBe7FN9ARL8wzmcldDyFMKIyWgS0iLNszPMjJu12PW98pSH7Dey9rPi4AFJ
         JKX5c+9U6kEagNmA01Ms+Wtd283xE3eqYbQ6gjGF2b7kthQJcplKorha2v5Tt7Ea2ud9
         Q/lQl+MSFpCyz4ktbsJtmocPxN5oWgrA6vmsQBClGNS4mTld3m6PO+BwjWSwYZxjwKP7
         uuW2FGuXOI4qKc/3ilSgOAmVMO5JIdAa7ayoT3eOAIGA/UBAyyEPr+GxQxso4eU4zILM
         px78tckZK/0RbumckvKT9Dtc8Dj8FGX8wdAWsGxgfQTOdsXaIT1lasxzmoCUNa1qOkZk
         FsKw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472237; x=1758077037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZvRTvSqxwREU5qD37D6rehmhARia0z2On/CaI5GiCSY=;
        b=JdpViqcehZvCdzM2LdFwvgtJWxxJYdRh0a9TGG2VO390luL7i40UIX1ZybERO/IjPg
         ecG4mUSg1ywQ6156bwBgwAyO0vEUnWFnyynuQ13YoN5xEtvT/DK0wMUzfYkTu4ooEnBx
         aBR1e8/KeQRVcGmAjlKHK8zxRXFHH7L6LR8+Xik5sJRB9S93V5lVfDYvDr2dyudjKXN4
         eCbwgvjVCYXk8qANoITQKTg0TPZA/T5x+8rXQgaCMvd2rh30PaUFB9JJ46rMnv2nhP3u
         /NCr0svHibGNXiPNNMCIaLTEwNPKyWrrlgEAm3MQYbs+FjH6yYG3+KIwhls6m1m8EMl2
         7Yrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472237; x=1758077037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZvRTvSqxwREU5qD37D6rehmhARia0z2On/CaI5GiCSY=;
        b=Z6FSdJmjYx3gebj1smR04kuslygx/zXhmXzsIO1bfp5yjqhThWNZJOw+TgWSwGw0h9
         DKfM7R3zFyN5NfjOO3lsXEMeWTBwHl9UN8VqerNmbsUQ5l4sBJbNSDElFL/ctnD8OYbM
         fce+GwJKapo/bOKmSXRjPnL3/p8mhk/uVRMOBkiGyUcSjUdV3YlSpexTZMu6fKnOsHJa
         ijq+Eo9zGCVui2j4JP2g7nvJMIJQsyCFC09kt4R554ySfiAZ20MM/WkgRHBe3txMUa29
         rCgWlKeOcWIoSI6p9AcxqMhX6CVXBkmCK2/YwVSPGF6j+Bcg4vHI8LblBMaEO0oBDihn
         plEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6qI7ZbVMsJVu5Yce34husO9llbHeU+l91OVYWBppjAl7SXxN9IB9zELI9tzDM0y1Ku7gd8Q==@lfdr.de
X-Gm-Message-State: AOJu0YxWBwHJDNCqFzCTZf/VClm0YEq9EkoAm51BWWpJS4BPy+WVs2AP
	mFRQrMOpoZYwK8B6t4EeWEt27xjkYGn546y2Hm+nN+Oz0kiIbMCkz5lc
X-Google-Smtp-Source: AGHT+IEZeAB2fGLlJmU4BZRfqvdrQx2zhWTtIlYe3RraDd8tRqvw3Z20MhK8RG4zzP7zX4t4gOpcOQ==
X-Received: by 2002:a05:6870:d0c7:b0:2ea:87d7:5a35 with SMTP id 586e51a60fabf-322652370d3mr6764807fac.36.1757472236947;
        Tue, 09 Sep 2025 19:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5nBM6lpMIID3c0jC5bca+tcnkDe7ZwEHBqqp4TsShIpw==
Received: by 2002:a05:6871:291a:10b0:31d:71b5:3ff8 with SMTP id
 586e51a60fabf-32126c7a364ls2247103fac.0.-pod-prod-09-us; Tue, 09 Sep 2025
 19:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU17GXCKwbyGzEgBJq8/GBZh3Zzj1Qvpg+aatKzQ1FBM41FEu2jXJ1UEcTa5MigrNt5p6q7BZelF4I=@googlegroups.com
X-Received: by 2002:a05:6830:3699:b0:745:3cea:c705 with SMTP id 46e09a7af769-74c7192e8afmr7398594a34.14.1757472235806;
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472235; cv=none;
        d=google.com; s=arc-20240605;
        b=NSA/CKHz8CDnGocATqBlesSqP8u3guNlYp4eVB8IuNBnCK0u+NLoj7t3qdG0SMPcJM
         loKAIKaCfxFa4QuQLQ7GgVplG6M1g4WDuQjlU0UZ/ddlTwYj/WH4m/KdC+EQRHFZU2VU
         BZj6WA85wPsQFNNZJX5NsRYcd0vde20MW7TjmKI0ekSwlEUtvUCqLkvdYgcdXyNbNG7Z
         cn//tR5nGBG1aIVRbJ7+C+7gZgkriDL9r0yYlAPjRabJ/2Nd2+ogCkmHC3KpOM/C6LZe
         9kxP11oe6ffcDS4+48IoNlmXA9wqdh+qeOTgQy2K59KPnqeIJ4nYdcKa4VQFDtoqqJuB
         YKNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=7bLAL3/wNh9TSZolDjbNqAfIBJnmt2XQBMTZKVFm5qw=;
        fh=q5uUQkRSEEm1HQxfpmQuJkH7h9wAbfgr1weznrVb8lc=;
        b=hYF8UbyENO3kR/ySjujkQhzdgBqP3VvFVBptvPQwbUBHckZDx3Wf9ctdsN3lDXFe+5
         F+aqTAbfbaVOBA1vbRpZT7f59dBgv/DTR7hf7bHbinsmGOfnY3AqwMQKKtzV04K8U3m6
         2nuFgro0nitZYcSDEWcbM/nMLzBNbFglMPgK3/vJv168u3wbqQytKI7Lljh4EUBEZvwf
         S8vTqMT4yftlaweIsBguJbP6xenJEtnVArUIy1MaX7KwwWMO+cQ+0eTlu/NZvP9Y83+o
         V95yPG6GPjdsONclJ92M34WQ8amGg16YQXW3xmbnk928B7MF4bVGj8FLwD/L8ICR6awy
         9VFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EFaK4Eb2;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6217307a0edsi380674eaf.2.2025.09.09.19.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-7704f3c46ceso5277610b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXf4F4TnKLNN9rX3vBugYkAw6Mew2Vx4dEBNHt98iiOwRiawlG2WoPi/W182KuL+hnq1Tz3b4GFZC0=@googlegroups.com
X-Gm-Gg: ASbGncuyXJu+j05gO5gAbTI2P4lhCsay6YlZf/1O+I3tJBeB1IVMN3V/1RjJD3NK51u
	AH7ELRAT45Gle72/9iJPj3MItWXEr/JSnBbHiEiDDsL/uHWWCGpL3nmVvvIwhm11N9pmGMddl/U
	5ueeddTKzX9TJDISVunhG4PEOVs2U6cUH7pFkmCWCMmLSVrFgo68AJgt59l3i+dBix9p33OVhC2
	eX5Jp2TciOOqvb/7KQ1zCMA8RWREyaTFBRMadr0NeoOmvm6tkvJBQzY/3l2pT3TzgZCKNfnTct+
	Ywxxt3Bbh+vFUKzaOcZdy/h60hq+/ge+B3oekt0nhynBgRT3z9ZBx4269uw0j2Qg+9qzJ5L44jH
	Ke5delE8H3r5hi3QxBUWt6D0+CERxJ3aO+7zT
X-Received: by 2002:a05:6a20:3d1c:b0:24b:bae4:9c68 with SMTP id adf61e73a8af0-2534347f664mr21300346637.29.1757472235109;
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b548a6a9f22sm1032505a12.34.2025.09.09.19.43.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:53 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id BD1A64206923; Wed, 10 Sep 2025 09:43:51 +0700 (WIB)
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
Subject: [PATCH v2 00/13] Internalize www.kernel.org/doc cross-references
Date: Wed, 10 Sep 2025 09:43:15 +0700
Message-ID: <20250910024328.17911-1-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3670; i=bagasdotme@gmail.com; h=from:subject; bh=YkGAhUMgv4n62Z+ysk68FYvIotbnN4rNKVg76eclr+0=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnkjdCX+kN/Vk8dEtTx4oXHJVUlr871/34wNfprkGL ftS0Hh2bkcpC4MYF4OsmCLLpES+ptO7jEQutK91hJnDygQyhIGLUwAmss2M4X9W7lbP1sh5f5RO Hw1mqOzaUvQkVGr5Yv7A7uJI7gMzyrwZ/nD+Ytx+cpXRX/eb/x2rj6W/XClZe5lBR2mP0knB37f n7WUAAA==
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EFaK4Eb2;       spf=pass
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

Cross-references to other docs (so-called internal links) are typically
done following Documentation/doc-guide/sphinx.rst: either simply write
the target docs (preferred) or use :doc: or :ref: reST directives (for
use-cases like having anchor text or cross-referencing sections). In
some places, however, links to https://www.kernel.org/doc are used
instead (outgoing, external links), owing inconsistency as these
requires Internet connection only to see docs that otherwise can be
accessed locally (after building with ``make htmldocs``).

Convert such external links to internal links, while keeping the
original anchor texts using :doc: directive. Note that this does not
cover docs.kernel.org links nor touching Documentation/tools (as docs
containing external links are in manpages).

This series is based on docs-next tree. Maintainers can feel free to
apply any of patches in this series to their own tree.

Changes since v1 [1]:

  * Apply review tags
  * Drop patch [12/14] as it has been applied to sound tree

[1]: https://lore.kernel.org/linux-doc/20250829075524.45635-1-bagasdotme@gmail.com/

Bagas Sanjaya (13):
  Documentation: hw-vuln: l1tf: Convert kernel docs external links
  Documentation: damon: reclaim: Convert "Free Page Reporting" citation
    link
  Documentation: perf-security: Convert security credentials
    bibliography link
  Documentation: amd-pstate: Use internal link to kselftest
  Documentation: blk-mq: Convert block layer docs external links
  Documentation: bpf: Convert external kernel docs link
  Documentation: kasan: Use internal link to kunit
  Documentation: gpu: Use internal link to kunit
  Documentation: filesystems: Fix stale reference to device-mapper docs
  Documentation: smb: smbdirect: Convert KSMBD docs link
  Documentation: net: Convert external kernel networking docs
  nitro_enclaves: Use internal cross-reference for kernel docs links
  Documentation: checkpatch: Convert kernel docs references

 Documentation/admin-guide/hw-vuln/l1tf.rst    |   9 +-
 .../admin-guide/mm/damon/reclaim.rst          |   2 +-
 Documentation/admin-guide/perf-security.rst   |   2 +-
 Documentation/admin-guide/pm/amd-pstate.rst   |   3 +-
 Documentation/block/blk-mq.rst                |  23 ++--
 Documentation/bpf/bpf_iterators.rst           |   3 +-
 Documentation/bpf/map_xskmap.rst              |   5 +-
 Documentation/dev-tools/checkpatch.rst        | 121 ++++++++++++------
 Documentation/dev-tools/kasan.rst             |   6 +-
 .../bindings/submitting-patches.rst           |   2 +
 .../driver-api/driver-model/device.rst        |   2 +
 Documentation/filesystems/fsverity.rst        |  11 +-
 Documentation/filesystems/smb/smbdirect.rst   |   4 +-
 Documentation/filesystems/sysfs.rst           |   2 +
 .../filesystems/ubifs-authentication.rst      |   4 +-
 Documentation/gpu/todo.rst                    |   6 +-
 Documentation/kbuild/reproducible-builds.rst  |   2 +
 Documentation/locking/lockdep-design.rst      |   2 +
 .../can/ctu/ctucanfd-driver.rst               |   3 +-
 .../device_drivers/ethernet/amazon/ena.rst    |   4 +-
 Documentation/networking/ethtool-netlink.rst  |   3 +-
 Documentation/networking/snmp_counter.rst     |  12 +-
 Documentation/process/coding-style.rst        |  15 +++
 Documentation/process/deprecated.rst          |   4 +
 Documentation/process/submitting-patches.rst  |   4 +
 Documentation/virt/ne_overview.rst            |  10 +-
 26 files changed, 161 insertions(+), 103 deletions(-)


base-commit: f44a29784f685804d9970cfb0d3439c9e30981d7
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-1-bagasdotme%40gmail.com.
