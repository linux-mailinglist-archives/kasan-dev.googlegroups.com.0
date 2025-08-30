Return-Path: <kasan-dev+bncBDBPD5PMXQCRBNWGZXCQMGQEZVAS3LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3970B3CF58
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 22:46:48 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-327709e00c1sf3306020a91.3
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 13:46:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756586806; cv=pass;
        d=google.com; s=arc-20240605;
        b=bCUVdWYkPQDFuJDVb1+xUmc2IJplFFXvhASI9t5CA7STTzUYNxDDiMJaofrRisLGoF
         jo1qUuiUIzjMxjTW1MnodiHc2EF07Yq2SoTbHbBh9wq4em39N8spBXrVLG41gADpcEjB
         PWtW9gcfVBQsh17cU/3W1nheor7a4sjvO8X3rTOkvpHT8B5V4NRgm95ovuWct9ZqfOVT
         0TETPtlPPBGRsS3Exs2wTzVOZH+3hIyjuYYf+5tpgDaS1MtIChjFZDsdG2R2c8qUSARV
         /BuxMzYRORn0yh4aklcRcet092tjwwrXG5n8QM4rtwzkWss7bvU9NHYju7cWWxzgf9qn
         /u4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=MUcryFmfw1MAbkmJpT/4rNxwN9iXvFTS0ko9209xlvI=;
        fh=ajHApb/KDXbt96fZtNsW9d6X70dtUVWW/YcPjjfQLgA=;
        b=kmATIHH7CfAP5sUbDnrbjL8mmpF8hmv4gbx1CHnOcAIghWkzrofrSjWbRIxzy2gFyf
         ON1kVVpe3ck1uKS7VhEiBz09uXduRTJH4+TX9PexOVBUexQJearIJ8z2VOr4L8gMOARN
         P2WwcTlwUsjd/z9mqMPRvImCJPBI1yZ/pRVqCPE2M6ffI0bCaNGssQ0m7dFE/BHIwRha
         u9QW8nx7fx97aKQHIe2/+XCvINXUa9SdpU54LdkjeSYm9K9cTLTjed4vyrXnMDR19VcP
         /frVgxfa1Td17b0U9G80L/98KEEG0MecysNv9LuXwfa3jZbWJhW+ZT0TDticoCiwSAxK
         C1/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i7heKHiF;
       spf=pass (google.com: domain of mchehab+huawei@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=mchehab+huawei@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756586806; x=1757191606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MUcryFmfw1MAbkmJpT/4rNxwN9iXvFTS0ko9209xlvI=;
        b=Kf24f+2Viz1NSqmGCNcPtXJcsFvCD4NiNCDmS8VMnogJfdz4OgHqREO4bYJrgUQnzI
         PqMpfCHJS03yjTJsS9P57P4+oGmhntxpy9lWlG5Sun+A8d/QBXgGoJAK02JRKKb96aW6
         ZKQg+8V3toxB6Jju8fHN4hLZAcqk38IL9gwFYcb/N9FQYJfF+xizcMjy/BP4B2PB06Fh
         mJ2PpYZyd+RUfBK+LLFvCrSaZRpdAzfX/bq9Ta/OujimtQRaEcXwivSW8U9ecmwrZrJm
         7zP5lKC3SbxFBc0aSz9Dne24J/IcvJUrQdRYKbgyygfMs6S/UpIX7RI3VUtBtVVd53kf
         8H5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756586806; x=1757191606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MUcryFmfw1MAbkmJpT/4rNxwN9iXvFTS0ko9209xlvI=;
        b=IHxPUCMIyiPUdkCYFMc8pgjwc4naFg4/J91S1n1EoWvHI7uJNGRmVkOxCtq26/Y+HM
         0BBAJdIMkIU2ZGvCuNk92daYHupLZca9brmIc6tkkSyyRsYKOpYRajv0CvPvfbbEv4yZ
         l/kENXHXuTsNyRk0vV4u1L/r5OLOvzEQ/Afuki3PU0vtBQMj9ZeQJQJQjy3fJV0i8rdW
         bVpPTAyUr5me/IsdgffPOrvsr2Wm9z4/rTHlyE+OxcG3DrnkjPlSF3q5qfEy1NM6SyZ0
         slJEJq1eI5DwQm5QRRaYZBJ5fcDauCmAROA17k5erMm3+sJZdvkIzVk/A9+DgCFFYwFo
         kXtQ==
X-Forwarded-Encrypted: i=2; AJvYcCUex35jCPVFnV8BOEgqbO5jN25mXtcApJCaswfusuZq16olHF0j66BavPS7mBc4DUPuzbYsbQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxo9dUSy6TGe3zmVtOab3KxUqRouya7xaoAWusLgHjQTms2y3Vv
	Rzl9xO5oev9sNMyu8Y0/1NeJ92Yc59DgNZnc/dh56/vSwLxw0lHhMD1Z
X-Google-Smtp-Source: AGHT+IHe89oLjWG13/Kw019jgxbhjVwmYk1xnEYtV7OlM6SUvMMmQGXZvHTF9SUDpSo7qXvhqngK5A==
X-Received: by 2002:a17:90a:d446:b0:327:f5ae:deea with SMTP id 98e67ed59e1d1-32815412863mr3149186a91.5.1756586806455;
        Sat, 30 Aug 2025 13:46:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7Tw2ddfP30ODMnXT0wGea25AZvkibKRhH11j2DrVl0w==
Received: by 2002:a17:90b:4a03:b0:327:e760:af15 with SMTP id
 98e67ed59e1d1-327e760b035ls1650067a91.0.-pod-prod-04-us; Sat, 30 Aug 2025
 13:46:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj5v49EUfJPG4cG26p2UmnGD4ASRdlrg3xBOQYbGJIQuS8/O2Ecpuc+UrA+R+XmiFwePKe4M1dp3o=@googlegroups.com
X-Received: by 2002:a05:6a20:a128:b0:23f:f88a:c17d with SMTP id adf61e73a8af0-243d6f37ee4mr4285630637.42.1756586804914;
        Sat, 30 Aug 2025 13:46:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756586804; cv=none;
        d=google.com; s=arc-20240605;
        b=hGxK2kGsy5Mqs98h58N17xdhNHyftlFVM6okYIzSfVHjJriXoszCgO+7waDTf0yeMT
         VtHxH5mdhsYZsA0MFRahZUQ9A1boDQbGj4Ug9QZdbyjCNVKWfz/ZaHpwqOhn/62mYKNi
         BKysepxykDtux2M/3LWId0cs5OJ7ezprkgG79UyVDozqP0I/R166Mk4z58uNwUsnUgBj
         5/AcbmhpeheiK6JVz5KKI5IDJvlDXZkB5YtB5oRPci3dJCRbKwThYDGhDAd3SmrBhB/1
         SirqIQA4SjBV2zGdv20uUtzogBxW/lur4Lz29DoK6pR7BOnkiZ9SRC6PmYqf1F8VXmhJ
         FenA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sERoEhOT3TgQGeAbgiCm8VB8EH4ve3pj8WEJe0BUAXc=;
        fh=pAXmqCBml/3O/fxVxKtWJ//VvB40x96t12DA2lvhUHM=;
        b=JAwF9jFjMu3GQtlDtbvy6lWt4KogqyU66lX6g60/msFCRlz77SNgMTY2dwvsGB/a3O
         pWDHm5VZvj2ETnTGhN+dlhFwWIRGaUDknHJZBEkzwk/hpoAgDOk3CujaJhqHUFHdUwPr
         sosuwu5muRAfB3G+i2vXwBc/b9pCbjMvKsgb++FPK9R+TIV+y7Fno2IG4J65LgLh8U1V
         crLoseyxypof8cgzT9DwAz7YrMnTBSkRp17EvPOjonQxEuZE/gAfE4C3Ut05mrqkE4oJ
         r6j4ZN+5w84DoRfjALjSwc80EYXBd/nyXgzWIrvrC/i3Dpgub9//9XAgY5vFA/nRSz6l
         +ukg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i7heKHiF;
       spf=pass (google.com: domain of mchehab+huawei@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=mchehab+huawei@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4cd28b47easi221590a12.4.2025.08.30.13.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Aug 2025 13:46:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab+huawei@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8645643FD7;
	Sat, 30 Aug 2025 20:46:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF130C4CEEB;
	Sat, 30 Aug 2025 20:46:25 +0000 (UTC)
Date: Sat, 30 Aug 2025 22:46:22 +0200
From: "'Mauro Carvalho Chehab' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux
 Documentation <linux-doc@vger.kernel.org>, Linux DAMON
 <damon@lists.linux.dev>, Linux Memory Management List <linux-mm@kvack.org>,
 Linux Power Management <linux-pm@vger.kernel.org>, Linux Block Devices
 <linux-block@vger.kernel.org>, Linux BPF <bpf@vger.kernel.org>, Linux
 Kernel Workflows <workflows@vger.kernel.org>, Linux KASAN
 <kasan-dev@googlegroups.com>, Linux Devicetree
 <devicetree@vger.kernel.org>, Linux fsverity <fsverity@lists.linux.dev>,
 Linux MTD <linux-mtd@lists.infradead.org>, Linux DRI Development
 <dri-devel@lists.freedesktop.org>, Linux Kernel Build System
 <linux-lbuild@vger.kernel.org>, Linux Networking <netdev@vger.kernel.org>,
 Linux Sound <linux-sound@vger.kernel.org>, Thomas Gleixner
 <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, Peter Zijlstra
 <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@kernel.org>, Pawan Gupta
 <pawan.kumar.gupta@linux.intel.com>, Jonathan Corbet <corbet@lwn.net>,
 SeongJae Park <sj@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Lorenzo Stoakes
 <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren
 Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Huang Rui
 <ray.huang@amd.com>, "Gautham R. Shenoy" <gautham.shenoy@amd.com>, Mario
 Limonciello <mario.limonciello@amd.com>, Perry Yuan <perry.yuan@amd.com>,
 Jens Axboe <axboe@kernel.dk>, Alexei Starovoitov <ast@kernel.org>, Daniel
 Borkmann <daniel@iogearbox.net>, Andrii Nakryiko <andrii@kernel.org>,
 Martin KaFai Lau <martin.lau@linux.dev>, Eduard Zingerman
 <eddyz87@gmail.com>, Song Liu <song@kernel.org>, Yonghong Song
 <yonghong.song@linux.dev>, John Fastabend <john.fastabend@gmail.com>, KP
 Singh <kpsingh@kernel.org>, Stanislav Fomichev <sdf@fomichev.me>, Hao Luo
 <haoluo@google.com>, Jiri Olsa <jolsa@kernel.org>, Dwaipayan Ray
 <dwaipayanray1@gmail.com>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, Joe
 Perches <joe@perches.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Rob Herring <robh@kernel.org>,
 Krzysztof Kozlowski <krzk+dt@kernel.org>, Conor Dooley
 <conor+dt@kernel.org>, Eric Biggers <ebiggers@kernel.org>, tytso@mit.edu,
 Richard Weinberger <richard@nod.at>, Zhihao Cheng
 <chengzhihao1@huawei.com>, David Airlie <airlied@gmail.com>, Simona Vetter
 <simona@ffwll.ch>, Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann
 <tzimmermann@suse.de>, Nathan Chancellor <nathan@kernel.org>, Nicolas
 Schier <nicolas.schier@linux.dev>, Ingo Molnar <mingo@redhat.com>, Will
 Deacon <will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, Waiman Long
 <longman@redhat.com>, "David S. Miller" <davem@davemloft.net>, Eric Dumazet
 <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni
 <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, Shay Agroskin
 <shayagr@amazon.com>, Arthur Kiyanovski <akiyano@amazon.com>, David Arinzon
 <darinzon@amazon.com>, Saeed Bishara <saeedb@amazon.com>, Andrew Lunn
 <andrew@lunn.ch>, Liam Girdwood <lgirdwood@gmail.com>, Mark Brown
 <broonie@kernel.org>, Jaroslav Kysela <perex@perex.cz>, Takashi Iwai
 <tiwai@suse.com>, Alexandru Ciobotaru <alcioa@amazon.com>, The AWS Nitro
 Enclaves Team <aws-nitro-enclaves-devel@amazon.com>, Jesper Dangaard Brouer
 <hawk@kernel.org>, Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
 Steve French <stfrench@microsoft.com>, Meetakshi Setiya
 <msetiya@microsoft.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Martin K. Petersen" <martin.petersen@oracle.com>, Bart Van Assche
 <bvanassche@acm.org>, Thomas =?UTF-8?B?V2Vpw59zY2h1aA==?=
 <linux@weissschuh.net>, Masahiro Yamada <masahiroy@kernel.org>
Subject: Re: [PATCH 12/14] ASoC: doc: Internally link to Writing an ALSA
 Driver docs
Message-ID: <20250830224614.6a124f82@foz.lan>
In-Reply-To: <20250829075524.45635-13-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
	<20250829075524.45635-13-bagasdotme@gmail.com>
X-Mailer: Claws Mail 4.3.1 (GTK 3.24.49; x86_64-redhat-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i7heKHiF;       spf=pass
 (google.com: domain of mchehab+huawei@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=mchehab+huawei@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Reply-To: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
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

Em Fri, 29 Aug 2025 14:55:22 +0700
Bagas Sanjaya <bagasdotme@gmail.com> escreveu:

> ASoC codec and platform driver docs contain reference to writing ALSA
> driver docs, as an external link. Use :doc: directive for the job
> instead.
> 
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>  Documentation/sound/soc/codec.rst    | 4 ++--
>  Documentation/sound/soc/platform.rst | 4 ++--
>  2 files changed, 4 insertions(+), 4 deletions(-)
> 
> diff --git a/Documentation/sound/soc/codec.rst b/Documentation/sound/soc/codec.rst
> index af973c4cac9309..b9d87a4f929b5d 100644
> --- a/Documentation/sound/soc/codec.rst
> +++ b/Documentation/sound/soc/codec.rst
> @@ -131,8 +131,8 @@ The codec driver also supports the following ALSA PCM operations:-
>  	int (*prepare)(struct snd_pcm_substream *);
>    };
>  
> -Please refer to the ALSA driver PCM documentation for details.
> -https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html
> +Please refer to the :doc:`ALSA driver PCM documentation
> +<../kernel-api/writing-an-alsa-driver>` for details.
>  
>  
>  DAPM description
> diff --git a/Documentation/sound/soc/platform.rst b/Documentation/sound/soc/platform.rst
> index 7036630eaf016c..bd21d0a4dd9b0b 100644
> --- a/Documentation/sound/soc/platform.rst
> +++ b/Documentation/sound/soc/platform.rst
> @@ -45,8 +45,8 @@ snd_soc_component_driver:-
>  	...
>    };
>  
> -Please refer to the ALSA driver documentation for details of audio DMA.
> -https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html
> +Please refer to the :doc:`ALSA driver documentation
> +<../kernel-api/writing-an-alsa-driver>` for details of audio DMA.

Don't use relative paths for :doc:. They don't work well, specially
when one uses SPHINXDIRS.

The best is o use Documentation/kernel-api/writing-an-alsa-driver.rst
and let automarkup figure it out. As we have a checker, broken
references generate warnings at build time.

Regards,
Mauro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250830224614.6a124f82%40foz.lan.
