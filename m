Return-Path: <kasan-dev+bncBDNJH7PUREDRB6FMY3CQMGQE545UQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C3E2B3BA83
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:00:58 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45b7a0d1a71sf13052325e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:00:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756468858; cv=pass;
        d=google.com; s=arc-20240605;
        b=jLOUqKULk3DnbtpawBZmumvCEVbtj1U2kTw8BZnlukBslbrBC2wVeNMGsmMSfccoUj
         duXknoV1bgq5mRD6GkbDmlssT8NHJXq10ZuAagtq7Sqn1afaWs/J3RAP+GkpHEolmDBC
         EGFjG1xW8HoBeVB+FKrBCyns0e2orPqnMxOC6Mc2metvZ+wXjYdeRZYtyvJiTlcroMjT
         d/oXIGM+YG2JHyL/R0+uKRqoQjIF3vSRiKt5R3glgRe9VupaEjwtUxcBwp89dTg3Q07f
         31tYT4wQy8nd8LiPYbQONRtQnIzjsvspshzUvCbuQEMQDre7D4c9L2AwDO5hXAz32ud7
         C65w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=5cgFPs8RHT3rZcV18+ksBbK2KK64IEjwEAriZWagCG4=;
        fh=1TVRQ0AmCTlo+zsIZ5HCP7g0G1PGLfKWg6a/PPUF8Jo=;
        b=JFWMtsOPITCcilyLauiNfZ39hD5Gvx0th2stuPAKKDCkkVHLKmSfKWsQSgjyaRIpOS
         V0oG0KpLIvpLM4UpCPxcJZ10jJ7PQbtmtQeAiatlYmrkmv/DGEoc1j0RY98pO6BBtMt0
         cJO4VFwJv8ONkQ4YK4/faVp/k8HT2Y16G+gXaxttNQYoTrRUZvMI4W8bSXtzcn/Oa2dV
         756FVhn93eaTpwPJlk6RLO6ArmrQmh+AQRFeXxrChj+fTYv1zJJrgBsqjWS9squDQD/M
         8rQUlzArkfo3NlKbMmsYmcDDnOx2NTCMo7AD1fPYbqTe4hx8g5BS4GKfwazKW3mzVvTF
         YCNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=EZXX5o4h;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="OPBU/lqB";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of tzimmermann@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=tzimmermann@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756468858; x=1757073658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5cgFPs8RHT3rZcV18+ksBbK2KK64IEjwEAriZWagCG4=;
        b=MgST77Zj8CwZjVeG/SH2Jf2zP+FHP9YRT9nurlMif5EzHv4MmNmrvEyDrFYpS/CsaN
         sK7WraruXhLDbamtmI3SLovdNNuhLb2fKU40TcffXQAYr72WNruSqRetIHxxGKB6PsUm
         VQiWR5nPtMvGSmhf2GB5F+bvBbKPrivw6YhZRmqlONHlwl/5vgin+ynh4oXVfbh4VEFQ
         Mn+CBmScSVC7ojSBJhkiVpMUdqr/ddcw/ANuLGMNNl9kCPYkFRISQiFiL4Wcyib+IkV5
         RmnGEwn9NBx4ZEOmBKSNZgkr/U56cf9H+Qw7X2Hp0iwRfvqFObaC4rTfILhvth5mzYMh
         4u7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756468858; x=1757073658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5cgFPs8RHT3rZcV18+ksBbK2KK64IEjwEAriZWagCG4=;
        b=FDsaENutDmzjD8vTvHpGNEkPWoFOf0cOz+HXy33Arq5tgoK4iGQHALjJN1x84Wx5Ty
         otfA6P7FePVvE4iodcsJHh7K71XUEdIWJKA4jSzBqGk8b+5wJEkq+hH08J6ZBi0r6Nio
         9I00DtPi4eYJArqF7z/eVjhQmlmRuBZWROe/5P24OwP7lBwvl2AwsgdkCdxojIXm69Wu
         j0G62166pypglKWpowKfdYgguNJ+4HVX2O4LBOaCSLX4634ozlw9+eh868WDDRLkXgnO
         FQVBaQGk7Ie6puaxN8N+mnjs0TxWXwbDfczIrqKDRPPoHWr9zZhDk7TdFp0O4Ls5iIDI
         nyGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXre9dNpzL4kJXc7jnki/W25Dhw2crsP76egq3AdgUZg3gsdeyd85XDlVGuOp4ViVq3PVpQsQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw7LCcWcW/3+19ZHmhXM9Q6xvOYoPSyPw7xRK/DmPoDFxPx+cMA
	B/OuQCSvAR+L1GBDmFvVDkq7atNm7NwY6zgF8/sZisZTvTO4Vcyo2ReX
X-Google-Smtp-Source: AGHT+IHw16aml+VSOolyNJkx4VvkLQw/cfiZV+Zltd3uZq7a+FvXhUhZGFvcekW5K062jG98dob0Cw==
X-Received: by 2002:a05:600c:1c0c:b0:458:bda4:43df with SMTP id 5b1f17b1804b1-45b727a2c43mr87049375e9.17.1756468857462;
        Fri, 29 Aug 2025 05:00:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfqC5A1QEfPvTyPoljiowM4GnkUtIEeCd1LUljZ0jz1GA==
Received: by 2002:a05:600c:1993:b0:459:d42f:7dd5 with SMTP id
 5b1f17b1804b1-45b78796496ls8668245e9.0.-pod-prod-09-eu; Fri, 29 Aug 2025
 05:00:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZqV79CuDcu6azIJ0iF3jj+cMRbT27wihhu2hcsIes8LVnpf32sixrn9ilOPPt1uPptyfS14e1Vvw=@googlegroups.com
X-Received: by 2002:a05:6000:2306:b0:3c8:ffcf:e01d with SMTP id ffacd0b85a97d-3c8ffcfe6bbmr14121532f8f.55.1756468854814;
        Fri, 29 Aug 2025 05:00:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756468854; cv=none;
        d=google.com; s=arc-20240605;
        b=Lz+MGpAxJStH++gbA+/tWBHJvKEMLMOIH9Ud8ytb3JngpXC+2Ussdspaz2yJKId0lj
         XRL9BG8nkdgbvr8v2HU6ZCNeqL7gYlHE4GaStu2dBShHRfWj0NMoZCz7w2zrYTpQScn3
         uXLOR0weE+IBBOdlgP5sYT8Od+QIQiOG8HpjTui3DCmAe1eijUOjrpLb4vuXHcb+rjS6
         MhfcYMb18HdGMn1MocDR8Pgcr/LiSCEkjgBw7tEUbakxGXiR/0n5MRIC4P+dL5hd9jjM
         Yn7vALaAsF8PtIkKcnmtaiaLu/YhN4oHLbiBxiJrlL/SJBC1h3aVV5fpvmfONglnwVwq
         IjOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=iaUzxmwBsmTBCo2WBOyDflFvUI/88ipptA2vlawnwBU=;
        fh=h4pDr/7ncy9ff4xLhywP/VTiPAnrfqt6GLksfh8qsz0=;
        b=NQUKPXHRWYmtUVPXjaKS29yI6zaevhpL2MlXmeOti4tiOmos4LCER/Qv7VSHrBTbQd
         UWOnUjhgGbmoz8jexcN2XYa2hzZZZij16Brq9yqCMjBIYvs1cuZpXaV9Ju57bmqIK6li
         xM155NPmixIpJ43dV/OcmIEQKQA4/Xb6jmHTWpcLf2LFgfMw+YmSdp6LXzsefdrLZn8o
         RKY9GgG/x/iQ+8lJMK902eLO156TBqu50yi0XIPJ8B7xhg7XRouVLpP4CcSDrXj3dH8D
         kKw7nWMFdgOobo6T+6Lljh9rOhdCn6upYoxGvgt59UQhzDTsSc4w9jlvaIaq6uGkoZjW
         5FoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=EZXX5o4h;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="OPBU/lqB";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of tzimmermann@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=tzimmermann@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cf2883c8f2si38227f8f.4.2025.08.29.05.00.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 05:00:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of tzimmermann@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id DE57F33DB5;
	Fri, 29 Aug 2025 12:00:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9D2EC13A72;
	Fri, 29 Aug 2025 12:00:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id l3olJXOWsWgSYwAAD6G6ig
	(envelope-from <tzimmermann@suse.de>); Fri, 29 Aug 2025 12:00:51 +0000
Message-ID: <871b2113-5482-4f3c-b58b-573d6cbeebe0@suse.de>
Date: Fri, 29 Aug 2025 14:00:50 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 08/14] Documentation: gpu: Use internal link to kunit
To: Bagas Sanjaya <bagasdotme@gmail.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
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
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
 Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@kernel.org>,
 Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
 Jonathan Corbet <corbet@lwn.net>, SeongJae Park <sj@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Huang Rui <ray.huang@amd.com>, "Gautham R. Shenoy" <gautham.shenoy@amd.com>,
 Mario Limonciello <mario.limonciello@amd.com>,
 Perry Yuan <perry.yuan@amd.com>, Jens Axboe <axboe@kernel.dk>,
 Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
 Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau
 <martin.lau@linux.dev>, Eduard Zingerman <eddyz87@gmail.com>,
 Song Liu <song@kernel.org>, Yonghong Song <yonghong.song@linux.dev>,
 John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>,
 Stanislav Fomichev <sdf@fomichev.me>, Hao Luo <haoluo@google.com>,
 Jiri Olsa <jolsa@kernel.org>, Dwaipayan Ray <dwaipayanray1@gmail.com>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Joe Perches <joe@perches.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Rob Herring
 <robh@kernel.org>, Krzysztof Kozlowski <krzk+dt@kernel.org>,
 Conor Dooley <conor+dt@kernel.org>, Eric Biggers <ebiggers@kernel.org>,
 tytso@mit.edu, Richard Weinberger <richard@nod.at>,
 Zhihao Cheng <chengzhihao1@huawei.com>, David Airlie <airlied@gmail.com>,
 Simona Vetter <simona@ffwll.ch>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Nicolas Schier <nicolas.schier@linux.dev>, Ingo Molnar <mingo@redhat.com>,
 Will Deacon <will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>,
 Waiman Long <longman@redhat.com>, "David S. Miller" <davem@davemloft.net>,
 Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>,
 Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>,
 Shay Agroskin <shayagr@amazon.com>, Arthur Kiyanovski <akiyano@amazon.com>,
 David Arinzon <darinzon@amazon.com>, Saeed Bishara <saeedb@amazon.com>,
 Andrew Lunn <andrew@lunn.ch>, Liam Girdwood <lgirdwood@gmail.com>,
 Mark Brown <broonie@kernel.org>, Jaroslav Kysela <perex@perex.cz>,
 Takashi Iwai <tiwai@suse.com>, Alexandru Ciobotaru <alcioa@amazon.com>,
 The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
 Jesper Dangaard Brouer <hawk@kernel.org>,
 Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
 Steve French <stfrench@microsoft.com>,
 Meetakshi Setiya <msetiya@microsoft.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Martin K. Petersen" <martin.petersen@oracle.com>,
 Bart Van Assche <bvanassche@acm.org>, =?UTF-8?Q?Thomas_Wei=C3=9Fschuh?=
 <linux@weissschuh.net>, Masahiro Yamada <masahiroy@kernel.org>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
 <20250829075524.45635-9-bagasdotme@gmail.com>
Content-Language: en-US
From: Thomas Zimmermann <tzimmermann@suse.de>
Autocrypt: addr=tzimmermann@suse.de; keydata=
 xsBNBFs50uABCADEHPidWt974CaxBVbrIBwqcq/WURinJ3+2WlIrKWspiP83vfZKaXhFYsdg
 XH47fDVbPPj+d6tQrw5lPQCyqjwrCPYnq3WlIBnGPJ4/jreTL6V+qfKRDlGLWFjZcsrPJGE0
 BeB5BbqP5erN1qylK9i3gPoQjXGhpBpQYwRrEyQyjuvk+Ev0K1Jc5tVDeJAuau3TGNgah4Yc
 hdHm3bkPjz9EErV85RwvImQ1dptvx6s7xzwXTgGAsaYZsL8WCwDaTuqFa1d1jjlaxg6+tZsB
 9GluwvIhSezPgnEmimZDkGnZRRSFiGP8yjqTjjWuf0bSj5rUnTGiyLyRZRNGcXmu6hjlABEB
 AAHNJ1Rob21hcyBaaW1tZXJtYW5uIDx0emltbWVybWFubkBzdXNlLmRlPsLAjgQTAQgAOAIb
 AwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgBYhBHIX+6yM6c9jRKFo5WgNwR1TC3ojBQJftODH
 AAoJEGgNwR1TC3ojx1wH/0hKGWugiqDgLNXLRD/4TfHBEKmxIrmfu9Z5t7vwUKfwhFL6hqvo
 lXPJJKQpQ2z8+X2vZm/slsLn7J1yjrOsoJhKABDi+3QWWSGkaGwRJAdPVVyJMfJRNNNIKwVb
 U6B1BkX2XDKDGffF4TxlOpSQzdtNI/9gleOoUA8+jy8knnDYzjBNOZqLG2FuTdicBXblz0Mf
 vg41gd9kCwYXDnD91rJU8tzylXv03E75NCaTxTM+FBXPmsAVYQ4GYhhgFt8S2UWMoaaABLDe
 7l5FdnLdDEcbmd8uLU2CaG4W2cLrUaI4jz2XbkcPQkqTQ3EB67hYkjiEE6Zy3ggOitiQGcqp
 j//OwE0EWznS4AEIAMYmP4M/V+T5RY5at/g7rUdNsLhWv1APYrh9RQefODYHrNRHUE9eosYb
 T6XMryR9hT8XlGOYRwKWwiQBoWSDiTMo/Xi29jUnn4BXfI2px2DTXwc22LKtLAgTRjP+qbU6
 3Y0xnQN29UGDbYgyyK51DW3H0If2a3JNsheAAK+Xc9baj0LGIc8T9uiEWHBnCH+RdhgATnWW
 GKdDegUR5BkDfDg5O/FISymJBHx2Dyoklv5g4BzkgqTqwmaYzsl8UxZKvbaxq0zbehDda8lv
 hFXodNFMAgTLJlLuDYOGLK2AwbrS3Sp0AEbkpdJBb44qVlGm5bApZouHeJ/+n+7r12+lqdsA
 EQEAAcLAdgQYAQgAIAIbDBYhBHIX+6yM6c9jRKFo5WgNwR1TC3ojBQJftOH6AAoJEGgNwR1T
 C3ojVSkIALpAPkIJPQoURPb1VWjh34l0HlglmYHvZszJWTXYwavHR8+k6Baa6H7ufXNQtThR
 yIxJrQLW6rV5lm7TjhffEhxVCn37+cg0zZ3j7zIsSS0rx/aMwi6VhFJA5hfn3T0TtrijKP4A
 SAQO9xD1Zk9/61JWk8OysuIh7MXkl0fxbRKWE93XeQBhIJHQfnc+YBLprdnxR446Sh8Wn/2D
 Ya8cavuWf2zrB6cZurs048xe0UbSW5AOSo4V9M0jzYI4nZqTmPxYyXbm30Kvmz0rYVRaitYJ
 4kyYYMhuULvrJDMjZRvaNe52tkKAvMevcGdt38H4KSVXAylqyQOW5zvPc4/sq9c=
In-Reply-To: <20250829075524.45635-9-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FREEMAIL_TO(0.00)[gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com,lists.infradead.org,lists.freedesktop.org];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	TO_DN_SOME(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linutronix.de,alien8.de,infradead.org,kernel.org,linux.intel.com,lwn.net,linux-foundation.org,redhat.com,oracle.com,suse.cz,google.com,suse.com,amd.com,kernel.dk,iogearbox.net,linux.dev,gmail.com,fomichev.me,perches.com,arm.com,mit.edu,nod.at,huawei.com,ffwll.ch,davemloft.net,amazon.com,lunn.ch,perex.cz,ideasonboard.com,microsoft.com,linuxfoundation.org,acm.org,weissschuh.net];
	DKIM_TRACE(0.00)[suse.de:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_GT_50(0.00)[99];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	R_RATELIMIT(0.00)[to_ip_from(RLunxtm633ak3os5q1rit88byp)];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[dt];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns]
X-Spam-Flag: NO
X-Spam-Level: 
X-Rspamd-Queue-Id: DE57F33DB5
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Original-Sender: tzimmermann@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=EZXX5o4h;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b="OPBU/lqB";       dkim=neutral (no key)
 header.i=@suse.de header.s=susede2_ed25519;       spf=pass (google.com:
 domain of tzimmermann@suse.de designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=tzimmermann@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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



Am 29.08.25 um 09:55 schrieb Bagas Sanjaya:
> Use internal linking to kunit documentation.
>
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>

Acked-by: Thomas Zimmermann <tzimmermann@suse.de>

Fell free to merge it through a tree of your choice.

Best regards
Thomas

> ---
>   Documentation/gpu/todo.rst | 6 +++---
>   1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/Documentation/gpu/todo.rst b/Documentation/gpu/todo.rst
> index be8637da3fe950..efe9393f260ae2 100644
> --- a/Documentation/gpu/todo.rst
> +++ b/Documentation/gpu/todo.rst
> @@ -655,9 +655,9 @@ Better Testing
>   Add unit tests using the Kernel Unit Testing (KUnit) framework
>   --------------------------------------------------------------
>   
> -The `KUnit <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
> -provides a common framework for unit tests within the Linux kernel. Having a
> -test suite would allow to identify regressions earlier.
> +The :doc:`KUnit </dev-tools/kunit/index>` provides a common framework for unit
> +tests within the Linux kernel. Having a test suite would allow to identify
> +regressions earlier.
>   
>   A good candidate for the first unit tests are the format-conversion helpers in
>   ``drm_format_helper.c``.

-- 
--
Thomas Zimmermann
Graphics Driver Developer
SUSE Software Solutions Germany GmbH
Frankenstrasse 146, 90461 Nuernberg, Germany
GF: Ivo Totev, Andrew Myers, Andrew McDonald, Boudien Moerman
HRB 36809 (AG Nuernberg)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/871b2113-5482-4f3c-b58b-573d6cbeebe0%40suse.de.
