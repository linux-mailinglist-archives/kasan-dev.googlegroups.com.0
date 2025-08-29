Return-Path: <kasan-dev+bncBCC4R3XF44KBBHUSY7CQMGQEGONHBFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1985DB3BF77
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 17:37:04 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70ba7aa13c3sf69516926d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 08:37:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756481823; cv=pass;
        d=google.com; s=arc-20240605;
        b=jr89/tkOX3X79zIrv2XHKwTudUP92f3hh11O5rZwlOclwD4wFa9sMqQrb3O3z+SOl8
         KWFb6n8FV9c4gLGwzP83Co8uLwN7iRZr/SaMfB+6Y1EHrpppPQWTPaZsqWl1ywJaLylu
         XyTLlEHXWXj5MaQDMjfRnLpChsKeTJorcrU7jIZZafMPHqHO9H5/YZ0NbgeE5mIkY+uZ
         GdCxbv5yYy99ZlVcjo65LB5m6urdksz48obI8mmdO0DgtKuHinM3duCJxWD/M5Ua759k
         xQp42RxaTzn/iaMSoP0XUPd+zC3EiXgt11zAOgsdVlCavuVbyKyFNpTZcTOnGTUHOwMD
         QxOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ivp4X9H7Qb1xnlDBPQnuOispWPmdrniphcZwjanSfH8=;
        fh=ti8XPSGdIVMqy1qqtVJOKZk0LyQijA80Qc38LY8OONc=;
        b=dDjHBHZblRnUwVQyjbqgqFsXKq+dxVYGnhyrwoNSMZxWnAcUcBQn6nJMT5SOTXZw9c
         NMFgF1x/5TWNQSpNtNBVD7PgscG+viXpYt1wCM8HDHb9rERJvp08eftuBoWukTuRFvzC
         k/5jaA6dXSrxEbJIFRvUmwp4WQUoIP77nOc3590G0sZ6XaWJ3UsNc0396iRaJqnWg6aA
         5eOnY3GnmO2Ke6kzpoWOWvim6KiT5eVmd4yEADfjZWB80BEGc7vOc8S5tYSmdJoqt4N+
         gsCX+YZSmxNs0VXisurJ4C99RhP2Ys5EH/AIJ1D8lOlwXmLK757MsahNbt2HuH6KWNaX
         Pq6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hxRjy6JU;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756481823; x=1757086623; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ivp4X9H7Qb1xnlDBPQnuOispWPmdrniphcZwjanSfH8=;
        b=JUTohDJY/xjQ1f9juU2eF00wPAbQEfCXoUiAG8n8Lg98OxQDdA8LnDZycSO/0jt8de
         nGlNHD5KlFhxJsvAe/vZyYzH1ZPsnxYLYX/ggnbsCPfDoE6I3Hi9hgI1tmHILM/O0jqa
         +cCnh+IMblwDBdxJAcZJccEM/HCIE/c0MTHaZI4AThtrFQbBTl4YVWRSLwSP6HSvV5Li
         1nd+jUG4ycEb8SetjckN43EuuWbAqWTOUmSqa14wgonFYbTtIF0zOFgL1PPg9ZQw3dJL
         09umBrrzx8x88e2KkpN2FmeIy8KWROFUPhCLtGDIm7CvanvZ6Azx2TBJh1hjkdypLfHZ
         mxIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756481823; x=1757086623;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ivp4X9H7Qb1xnlDBPQnuOispWPmdrniphcZwjanSfH8=;
        b=i89Ud6vgrJeQ+ACQLPPxIO+JBvDLuHKOLVUNPG8QlpYg2faRNcfLXQWU4/Y4PKXNFc
         yosVqho/dWVewm7DNa+tSasje6hQqAlqoA8/Xqq4ND0eFL/0W0Ds215Nf3IAn8out5zV
         VUKCObgjKRMEv82yWLI4ld7FyaOQy+B9iHwSwIa7B31WZ2DRvtONxkmPGJsStm281nBU
         dPHR1lBJ6DiNm9Lyrw9PJHcyrQaHqYm4s/3ccwNixvI4jDffTAiD/eWHHNLevDHwOSYL
         0lcLPOye6rbkpp6vJe5MVtOl7Oq9qUq33CSLsPGBX4sp9AjkwzANEB4NzyVhmkLBE1p2
         eN+g==
X-Forwarded-Encrypted: i=2; AJvYcCWCMeVCUgAWrulS71XSe+Az7MOqTrVRt08T5cpeekKRsEqThdr1x9naPu1ClFlPtxBZFt9+ZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyv5icMkmO9SzqpBObhBUDSDbQdSaD3gTmXORQXb1CW6x1YqCqF
	ihoXCDahXW06idB40FaHo6R/x+7OH53cKM0aPNhuriPkJ9YNFs5VUjzr
X-Google-Smtp-Source: AGHT+IF08vjtuOUmlGq9cIAT8p3AVAwABVITHlSCcxJfSKCrRReJUT1vKlp5WlPY4Ukb+mHxrfbGOA==
X-Received: by 2002:ad4:5aea:0:b0:70d:d23a:9ea7 with SMTP id 6a1803df08f44-70dd23a9f70mr182326506d6.50.1756481822687;
        Fri, 29 Aug 2025 08:37:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZegsXNLCWgpzmgKSgTpnM12ALA+1XtPotnplVwq58fUzA==
Received: by 2002:a05:6214:459f:b0:70f:a06e:1d5c with SMTP id
 6a1803df08f44-70fa06e2432ls9585536d6.2.-pod-prod-04-us; Fri, 29 Aug 2025
 08:37:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcMafrHBWOGGBKY+VQECELlW7VJiXWD9wMDqTIsbOp0Q39rP1Tt1mTSBSkH2uugD1MIsx8HoO4P1Y=@googlegroups.com
X-Received: by 2002:a05:6122:3105:b0:529:2644:8c with SMTP id 71dfb90a1353d-53c8a2fc1fcmr9543570e0c.8.1756481821892;
        Fri, 29 Aug 2025 08:37:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756481821; cv=none;
        d=google.com; s=arc-20240605;
        b=MOtSZEYzP8OYkyKZbIqchD8mKVLrflDc4jkdARz5ew8Y9OoB7/PFL8OZ2UWCX0sCkb
         gfR2zs2vTs3u3uBSnRp3KQx0t/YuOxIFY5rZ4gfpsgYoQie5Vxwfv6DOG6dR4t4Z/gn8
         qvN5F6VGE2drKPr5owSkDDr0SVmo/Tm79mlXSvtOroxn5srOy9JOYQfx0pLfzlKOJzzV
         egwLLgcgB0SoM0UMAmLd4LCu/UbFF4IMxh+bWx74vtXGJGoMvZ0W4kTpGtlUHWzGVyVi
         SosdJMpaUwpBJDhL51hUmNHDNbhvFDVcdIBC4Ll1OGPdFFw+vxQcgXlEoRxaaeZ7AUeN
         lriw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QlEkqcjNcBy0l/GUV3Al+3r/V5OrJADrNoiJdSPBV78=;
        fh=LF/+jTQ8pH49T42jqbp6Xuca4vRffcWEbcpxB64G1Go=;
        b=PGVZAR0yxxdu3z+QDzdAtLUeTFaUoo18BRejlTyY6XI9fosZ+4yOnbL9Cpk1s2vTUP
         UAf1gdf6TQNGCpFb3mza1JENYbnp82+j1ZmwgJcURar7Ij2jDFlNOaBMDMyJqxBNwPXr
         jqFjYyhUANmGTBtMx/8+2vraFGCJtycfgz7/63i8zvouHIZCfYFrXhz+jd7+c7M9nP+v
         WECldDUvkO7R+pio5l7ayxD4lUk/hgEKnUwDBPRVo5UkjERC4r0xlRe7K5xB36/gyqyz
         M+laGu3KZaIYqNh/hXMY/7+Xd1L0bbRc+wGhsqxtBysDOk/R/tMEM7lTnnQRzdm1ECs9
         UEZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hxRjy6JU;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914717b4si78808e0c.3.2025.08.29.08.37.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 08:37:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C3D6C40BA3;
	Fri, 29 Aug 2025 15:37:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 61569C4CEFC;
	Fri, 29 Aug 2025 15:37:00 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: SeongJae Park <sj@kernel.org>,
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
	Linux Sound <linux-sound@vger.kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
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
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>
Subject: Re: [PATCH 02/14] Documentation: damon: reclaim: Convert "Free Page Reporting" citation link
Date: Fri, 29 Aug 2025 08:36:58 -0700
Message-Id: <20250829153658.69466-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250829075524.45635-3-bagasdotme@gmail.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hxRjy6JU;       spf=pass
 (google.com: domain of sj@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: SeongJae Park <sj@kernel.org>
Reply-To: SeongJae Park <sj@kernel.org>
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

On Fri, 29 Aug 2025 14:55:12 +0700 Bagas Sanjaya <bagasdotme@gmail.com> wrote:

> Use internal cross-reference for the citation link to Free Page
> Reporting docs.

Thank you for fixing this!

> 
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>

Reviewed-by: SeongJae Park <sj@kernel.org>


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829153658.69466-1-sj%40kernel.org.
