Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXFHRLDAMGQEOLORS3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39F06B52CE6
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 11:18:22 +0200 (CEST)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-60f478d600fsf540508d50.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 02:18:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757582301; cv=pass;
        d=google.com; s=arc-20240605;
        b=ca9srLuCCGgMLfg2FikP+8D/UzRErRAzExwwqD7SKcpMDRFUCRXQCuZeRnyP/FC0Bf
         6lT02v2W947+VJFGfDRJdDThWJpVgHK3ACgEzq1A0gCaT9Ql4gUW1oxgycSXkkkYW6Wy
         mnAOazfzKpgtMxz9TCM5EeKS50LrxX6WmRliOpv5ZiT710AmIdxv/DDf1MQs9NXGj99g
         AKJa0iZskccYdRMRVIg+ezfDq3/aZY4sXvAHzg/4DDMlYkHKeOFXY+BO+GGOYnDJpLF8
         +0ig/9BHvdQ/Wwoj1HZCmyFPgbILfeH5vhn4K2g1MQE70MLPWv0eKSnFfrRHnxK5BTTl
         9BOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FpKNAiDSnOEzp+UGZrH81+ftFOprTEZc/qtf2Kk4esI=;
        fh=KprvUg3sQC2yWtQU7WVHXbjGkHkoVC4LavnHwWv7B1I=;
        b=C1xM7eijU6ZvaapF+2zktbyt+UHWQG//W3dH0/cKOX6p+8XF5M9UNLOr4m4syE85IC
         t/0+5nvWA7mVF0XyX+MzKYDNDaWT3hDpPiHHiusaHkaSoiR07/kJBwxfs36en6SPQaDh
         qldWsRwmASGFAFwp6uwaU0XMFsfSyaxM8i6Ao25P9cgBui4V0PUCMWNcO5TljM0gHFzG
         +rw/Y1io4iwa6rgzuM7cSbNFxyQqIVGpSxWHZ9sRhQz61AZErnb9zgyuv7ei9BBadqNx
         qyuU/y4cKJNpY7xj1M+OhfuHUOVRV/pOl3fWv5FY38NMq7OBbg+6ihGsJkhvjhIwlNtB
         8zkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RruHrg3+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757582301; x=1758187101; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FpKNAiDSnOEzp+UGZrH81+ftFOprTEZc/qtf2Kk4esI=;
        b=iN/m7TrBEkIrNywe9knSqg88BCXpIM/WqAObslgPgJTrGupLs7IxYIq5RQ0+HJ6W6T
         9wiOopZJQqJC23RGBuhSyF2ErK469llhb150AKyHPcIE8HD+cdJG9ozNKomvnikwaFVT
         lvm2DgQkjv9ZE8r7mqYueVIPe10a3Zk1gAMiImHtDCzzggP0bk2vBRM/3ArGAVTfqwdb
         vtnw0g8SWPIFLCLDUjWBh8UzCiVKO5UoDmy98xnrrk78IaUOGAJBY0tswo2B6FQIXT8p
         m5dWUgdZ7WHUzMNk61gGXgauPMjAfE2IOiyC+rPT2WycXhkVve8MnRCiKor4np6YJtKn
         8rYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757582301; x=1758187101;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FpKNAiDSnOEzp+UGZrH81+ftFOprTEZc/qtf2Kk4esI=;
        b=i3oaV+Wx6E/0Wmse0vXFb8VCXXWwNrCAUrVZHgaLA6tjgNR/oApJRTqntRwwdNyPaQ
         YKgFnjnWfqxTyQOqbn+sTl/tKlKZmFGuPyda0jXhOvccgl68M/lGCC2/1wQXtMN5jF5I
         R682y80YnZVbQL2fyX7VEbal0t0WGlXM13sif4s1gKsiG9Y7ZmauGshW24TmLnWQgbpO
         cVNgeKBoth4JUY6Df2fdMLPLgg/cRIA+2xN9ugniSZ0oxwH4A/ejbNdHRyuNez2qKCOQ
         3PmujJCCSlBrvzQFKsVnp+hJaFKCu6R6dKV7+xGzGB5UrAadMgDecpYe7+eIPhISl2PR
         qHsg==
X-Forwarded-Encrypted: i=2; AJvYcCXcTtZKg+IbRGFEJsH53r9HDXkkYv/wijOXP2iMIZY5+MsE+41mqeKUxao7cOWk/vrKXPhV8A==@lfdr.de
X-Gm-Message-State: AOJu0Ywh9gKGH9h8CdOxgV9OX7q7WmA29doDDiJ66n+e1YUGMwJq8vWa
	0bDE8DEPRWQgvoml81zuPajt6b8rKhXQO4aR5vJITLHyGEW8DE3edU4C
X-Google-Smtp-Source: AGHT+IHvRsDI+8B8gaWnZwWAZ+lslcEZHjRAG3YqWbxY+XeeOllv6GE4gXZcpo744uDrlmYmWzb9vQ==
X-Received: by 2002:a05:690e:4345:b0:604:3849:9424 with SMTP id 956f58d0204a3-61022a5bad1mr9888023d50.8.1757582300876;
        Thu, 11 Sep 2025 02:18:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6NKOhYeIPXqLrdtYZquApBCxrdrpEymeJgKWoTyd6GfQ==
Received: by 2002:a25:f626:0:b0:e96:e38f:1a63 with SMTP id 3f1490d57ef6-ea3ccb4b99cls300515276.1.-pod-prod-06-us;
 Thu, 11 Sep 2025 02:18:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4EzA23m3oGpRDWuq9Gn2ROYqzZafV4QWopvoLSfO4TzCZGNz1gtKHJYonW/+RzvX1xX6ozHcNQYQ=@googlegroups.com
X-Received: by 2002:a05:6902:2b8c:b0:e9b:afa3:5190 with SMTP id 3f1490d57ef6-e9f6798f1c4mr15977291276.31.1757582299740;
        Thu, 11 Sep 2025 02:18:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757582299; cv=none;
        d=google.com; s=arc-20240605;
        b=UyTTn46CrQQ88nEBr7BJYoZrp6l6DhmiucVuqSs3h08N6GvyldLgJbc7u9qezjwcwk
         LbWcvbkDpa5r/c6ilTSLSMEsfndxTWyaTzky0+sxcluziB0+fqArgNyhJMR8TCbkrmbX
         l5jv6WhzQWOJ/stXHPx5m/o4l8xmp5jLWQmAMUMRay0QYQgRAcuE+vAPV/IyMNwSqZ0C
         bfsKZE2KUMhKnbxUlSeogJYIhmhH9Qs7p4rae4dhyfNUgsG6ONOEPOJN+HoTqo7HGoIQ
         eTIa75V6OK3ol0853/LYk/rk+nQWhzvSgD2wun0Ngzp5QMEXbwv8WFgw3Vtq6Ja9owMh
         D1xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1B3D6WIyM4uKCWTK+JvwjK5rmKnBn1DsJarcuewJmQY=;
        fh=M4CpC8cChGoaVvEa4S4aJt+szhiKOrP2uD8eF/7oUXM=;
        b=dPnizPNenRr6bq1RAH47/6cSC3xZSP1yv+zn2d+p8kzLR5BY9puyQQEqA7Q6qVRbaV
         VplOI8vWwiyFLC00vDnyiMNytyaTMu9NRllIUHYNQ0Mv7lCOYYTRJhvlQME6Wdo+Ez+Y
         YZ8jGbuW+aFX9Fpsw1w0N5xXH3TigQXN92FnYBPcGW/rTQ37spJqEtF1r6pc0DwR6HFG
         +bupUEXL+cItN6q12WLkeyWzPy1qQ51ilC7xvZ81QUOMEmw2eNgtvFXO1hBpzYIcR19d
         qtFYoAJtFvjXsuIyYbIHUcWhOHOCtFa4OfPcNv1c3gFlQ6UXdK1ZZkYPTcpvH5jvguQ5
         WA4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RruHrg3+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea3ced64785si52305276.0.2025.09.11.02.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Sep 2025 02:18:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id af79cd13be357-80e3612e1a7so82097685a.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Sep 2025 02:18:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFJginf7blOvbHGmOo58kP2nvJFbDMgDbQ/F1VBHGReQN/RH3gYfql23RKjn9n6uFYH8ogSNfzK1E=@googlegroups.com
X-Gm-Gg: ASbGnctU+55LNC7MNdQ/MYL8zrOcdqPtjYprVc7bXKC/tUpdEnVKFxdSBpNRvpXKnzV
	SOk7yykALYMo/nT/IPByt5ZGO+hCB8jI+VBX7DYPGKcGyHSDFofe1Xx6ib9rXub3zAu8MVMQ+kH
	1lH2cH84yN9TRw2r3B2wjHr6GIEp42Jw62PSwFRM8wXvz3yLVR4Fza3OW+3Ee6zXz6ZQYSNMaA0
	Tx2RzxfByLg7g+nPnnFPzu1n7mgMJ6VTUxn8v0sHK+O
X-Received: by 2002:a05:620a:45a7:b0:813:8842:93bf with SMTP id
 af79cd13be357-813c1e8e0femr1958044985a.40.1757582298381; Thu, 11 Sep 2025
 02:18:18 -0700 (PDT)
MIME-Version: 1.0
References: <20250910024328.17911-1-bagasdotme@gmail.com> <20250910024328.17911-8-bagasdotme@gmail.com>
In-Reply-To: <20250910024328.17911-8-bagasdotme@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Sep 2025 11:17:41 +0200
X-Gm-Features: AS18NWC9Ax6HJ7xE41xsztIAoL9MxJcZhppucVI7C3-6QUaMqtQ6glgozKyha94
Message-ID: <CAG_fn=WPCtL2Knk7_so+9QMcUPY2wCG93BZN-rwJC+ELLgJ4nQ@mail.gmail.com>
Subject: Re: [PATCH v2 07/13] Documentation: kasan: Use internal link to kunit
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Documentation <linux-doc@vger.kernel.org>, Linux DAMON <damon@lists.linux.dev>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux Power Management <linux-pm@vger.kernel.org>, 
	Linux Block Devices <linux-block@vger.kernel.org>, Linux BPF <bpf@vger.kernel.org>, 
	Linux Kernel Workflows <workflows@vger.kernel.org>, Linux KASAN <kasan-dev@googlegroups.com>, 
	Linux Devicetree <devicetree@vger.kernel.org>, Linux fsverity <fsverity@lists.linux.dev>, 
	Linux MTD <linux-mtd@lists.infradead.org>, 
	Linux DRI Development <dri-devel@lists.freedesktop.org>, 
	Linux Kernel Build System <linux-kbuild@vger.kernel.org>, Linux Networking <netdev@vger.kernel.org>, 
	Linux Sound <linux-sound@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Pawan Gupta <pawan.kumar.gupta@linux.intel.com>, 
	Jonathan Corbet <corbet@lwn.net>, SeongJae Park <sj@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, 
	Michal Hocko <mhocko@suse.com>, Huang Rui <ray.huang@amd.com>, 
	"Gautham R. Shenoy" <gautham.shenoy@amd.com>, Mario Limonciello <mario.limonciello@amd.com>, 
	Perry Yuan <perry.yuan@amd.com>, Jens Axboe <axboe@kernel.dk>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau <martin.lau@linux.dev>, 
	Eduard Zingerman <eddyz87@gmail.com>, Song Liu <song@kernel.org>, 
	Yonghong Song <yonghong.song@linux.dev>, John Fastabend <john.fastabend@gmail.com>, 
	KP Singh <kpsingh@kernel.org>, Stanislav Fomichev <sdf@fomichev.me>, Hao Luo <haoluo@google.com>, 
	Jiri Olsa <jolsa@kernel.org>, Dwaipayan Ray <dwaipayanray1@gmail.com>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Joe Perches <joe@perches.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Rob Herring <robh@kernel.org>, Krzysztof Kozlowski <krzk+dt@kernel.org>, Conor Dooley <conor+dt@kernel.org>, 
	Eric Biggers <ebiggers@kernel.org>, tytso@mit.edu, Richard Weinberger <richard@nod.at>, 
	Zhihao Cheng <chengzhihao1@huawei.com>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, 
	Thomas Zimmermann <tzimmermann@suse.de>, David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Waiman Long <longman@redhat.com>, "David S. Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, 
	Simon Horman <horms@kernel.org>, Shay Agroskin <shayagr@amazon.com>, 
	Arthur Kiyanovski <akiyano@amazon.com>, David Arinzon <darinzon@amazon.com>, 
	Saeed Bishara <saeedb@amazon.com>, Andrew Lunn <andrew@lunn.ch>, 
	Alexandru Ciobotaru <alcioa@amazon.com>, 
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>, 
	Jesper Dangaard Brouer <hawk@kernel.org>, Laurent Pinchart <laurent.pinchart@ideasonboard.com>, 
	Ranganath V N <vnranganath.20@gmail.com>, Steve French <stfrench@microsoft.com>, 
	Meetakshi Setiya <msetiya@microsoft.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"Martin K. Petersen" <martin.petersen@oracle.com>, Bart Van Assche <bvanassche@acm.org>, 
	=?UTF-8?Q?Thomas_Wei=C3=9Fschuh?= <linux@weissschuh.net>, 
	Masahiro Yamada <masahiroy@kernel.org>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Jani Nikula <jani.nikula@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RruHrg3+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Sep 10, 2025 at 4:44=E2=80=AFAM Bagas Sanjaya <bagasdotme@gmail.com=
> wrote:
>
> Use internal linking to KUnit documentation.
>
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWPCtL2Knk7_so%2B9QMcUPY2wCG93BZN-rwJC%2BELLgJ4nQ%40mail.gmail.com.
