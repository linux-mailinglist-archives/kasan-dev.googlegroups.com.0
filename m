Return-Path: <kasan-dev+bncBDQ2L75W5QGBB3GOZDCQMGQE4K2O2TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D3F81B3C4B4
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 00:19:25 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30cceb35df3sf3202823fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:19:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756505964; cv=pass;
        d=google.com; s=arc-20240605;
        b=DTVDKENusIqAsP4yKbMGg/0HWNWBuuDMaLJNMwmYZQz+y7R0QtjkN2oEVIt8jq3gcV
         XwnlyBd7I4v7WzHoZ6Qo3WR/mm/a0ZR+pT1NYIoeg7JtymSKnN0XU8kaDWZ2TifhvJ2i
         FLdYtgy2om1z6ONrWGcbFzdAQcKgUgP6J0cXHDuHnpdupTsEyoolT+V8xDgqYm7vP9l6
         KMiL293zF8WUEXI6RXIPpypiUd7YbEM0lb4QUbhvQYmnoKRO2BE84DhKQpoO55hMmFvt
         4yQl6XcUClpW34qCRhxKdbi8ZU+nhc1K8nl6vS/mVjz15ugmg/4u5I6fnj9TKXKLQL3c
         BQEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:date
         :message-id:subject:references:in-reply-to:cc:to:from:dkim-signature;
        bh=wwNGJaMHqVgAipNn0EfP+DBzyMuRbrZ8jddReKt/+fU=;
        fh=O7p6+hn4mrunZDpcjA5bBRB6lzsGobtL1cIEvOaw+wo=;
        b=NSmOc4Y7UCkITm9Ites3OByaDQbe2oMEj3FvQA86VwnLeTNjEuZCMpl4Sre1lvSHXJ
         Kxkozid/a9SU8FkTiOMtrt8eBWMG4ONzHi97AZJp5ScXuabRDLtItuF0Tlu2JxdpGgbV
         FFc9uPGbVD+Ze8mpK2rCM+6hhUdteWEb1Fsubj8w5KY7wEgVaDIaSZ19FFfcTJ3qJvTH
         P0Th8znjvYjJo3W0lut/RI5oIk354STLwXj05BllAHSzIPaV9ff94LZOj4dSofxBmLQx
         IgA+YdLFJZvYaE9rnn2Q+2ehbQ4VnY3KIXNa88YjU5qpRED3zN4h17FzFEQjeUf2kYtx
         IVQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NpneGQ3Q;
       spf=pass (google.com: domain of broonie@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756505964; x=1757110764; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wwNGJaMHqVgAipNn0EfP+DBzyMuRbrZ8jddReKt/+fU=;
        b=fm4yn6WggLMNULAZq9CUyC1v++wwR6+AEZq1Q3kSo39huZrONkV6UG8edlD4EPU6QT
         3rESn8N4insdH12OFx5SoCoxSY1XPEYJ2FA2n+rKKiUKTjWw5zM3L7oHS9i+KO9l++KA
         UGBFz35MKydDkA+cqCLENRNUIR0kEnMF3AwF7VVJnwVPmrhDDJYtMe0BZwo0cRrOVpMy
         S57psR7NqolVkoDuOu0gNE7SMvkLVX32ZDgLIANdk9hzU7lcfmtc2cLIU9LhM4/RM8QX
         k9cUyRQcwuC0WQWjj6DAqreWsxOQXnf0jYr/qzqCJFjUUhJbmuUL8uf4TU4642m4TJ6x
         bITg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756505964; x=1757110764;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wwNGJaMHqVgAipNn0EfP+DBzyMuRbrZ8jddReKt/+fU=;
        b=L2vNv9HwiXh+Ipva/7L8ol8k16lR8anjgKZnRrpJT5iYF6LJaIP5S5UPVnLHIwmJ6F
         HUS575bVGBFkqPtSkAsGAfuFet5TPJ77Cj80ro+p29pdpVtmsH3Tfm0Pvh9vYDua3jcg
         ddt+OvdNQcPdw7EU9vaAQI2q7Ap6dqproxoHVKamxUCQ9a1hjxIh9qikBsaD8HeVPUxE
         gA0MpC4t12uvy3w1wujeut/Z/jnsFdAxM/owy4gDG9HIQPH6zmvTyyCO5Y3BkZY8sjN0
         hJCnG60ELV6jD4i38vFnTdPabxlHYxg2NfXSOQKGi/nVt+xszxgnHDPbCNMvndN4BAbY
         1QLQ==
X-Forwarded-Encrypted: i=2; AJvYcCWJ57FIx5Sy1mwQLm01pU/1oWhiocTDgz4362JVvMfwfb+KLK8Dz+az7UsYyZAo8XU5mS+5/Q==@lfdr.de
X-Gm-Message-State: AOJu0Yx8wqd5ivh92sBwFHoPAd4UAB/2X8sODQianyWwIZMOuzKAopCr
	Ku8nFBtMxGPFuplzm5CWIfHZ0uiWwO0VAxMFiNG+jYzppVIfDasR0y55
X-Google-Smtp-Source: AGHT+IFBWBxaU8DUfkE/Ju2/G2W7gWaQFp1xoLRkQGfO0DGfFvQnuzmM7BpCjoN4TYkE600/iZa8pw==
X-Received: by 2002:a05:6871:5227:b0:314:b6a6:6894 with SMTP id 586e51a60fabf-319633dacd3mr87390fac.40.1756505964341;
        Fri, 29 Aug 2025 15:19:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcNzywACKEwp9oRicCdRWWmy7sT9Bh8CS7G3mQwlhfSeQ==
Received: by 2002:a05:6870:e3c5:b0:30b:b2fd:9588 with SMTP id
 586e51a60fabf-315962e3776ls1002972fac.2.-pod-prod-03-us; Fri, 29 Aug 2025
 15:19:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5MGM/6jXBvWPTNQEu07CTh0bMgqd2MKOQMC7yW1PPa6PE1QmDKNbh91DTpiJvzhdFAFKCIacp/3E=@googlegroups.com
X-Received: by 2002:a05:6808:152a:b0:437:d744:dd4a with SMTP id 5614622812f47-437f7caf739mr105963b6e.5.1756505963335;
        Fri, 29 Aug 2025 15:19:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756505963; cv=none;
        d=google.com; s=arc-20240605;
        b=h4j36JjFGgkkApr3rx4HDpL/1LRsZCl3xok5DBLtFtVx+Uweq0saahmjfPFBYpMG03
         dEHqB9NDxG8496FLUdFpyo5OISmmL95nNcvwzpqG89utPFBib7haDkfQRu7PtJcQBBlQ
         3INf29R8dEMoTP6pv/NTeNA6d5+2lUFAtscoFtPtSWwAalq7YMRnlLvoYDySXSiGE5Ph
         3xMsnMPK6A/e7Zunw9COOLOLY0NO3KklkmyHC+MclSrCO+7uorYjmAWM3N/Cuz1n8ty2
         hubErwClLleH+bGnY4Q4ELjAOYN8PDoAcm1r4FgxoiZZjHvwny1vjHbQG4orB/BUUdYb
         r3tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=cXR6czlWvZZYuRgOZlVCoMto1uLIOZkL+rEOt0IMQlU=;
        fh=b7B08FfHPvn63Mj47rCtgM8LDJ0ym2izQIPgPX05QUA=;
        b=UCvTg1wJrX4oUhFIRCZerDGW53Fb5ouF4haAb0lSc3DORd1tCPBD+i9AnB+2iSxLi6
         re5q+F0VCrpmcnZYtDVdSUvkpfEgHrE4m9OeyT73iWx3ttHUaZdsJRD9SQv5XVeRrG9+
         Mapje90lKrTiqKjCC8tXsyljpYIfnMoc47T3UhHLEoAHFdE9QqmwdR6lrCFiA2X9yV32
         RnHh+LJ4LoD4ug+hJvW8ZLa2uDUBhbWlhGm94K93sL1AyWBzaFPoQzqNyjzF9LoXCfZk
         tbAQf+iZMFGe2Y/hp/GQdx0Z9dexfDIIZt1e/4XUPdg+iLDCG0R9qAXKltJRtROFg+Jm
         rGfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NpneGQ3Q;
       spf=pass (google.com: domain of broonie@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437f41a220asi45464b6e.2.2025.08.29.15.19.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 15:19:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8BA72438B8;
	Fri, 29 Aug 2025 22:19:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2D549C4CEF0;
	Fri, 29 Aug 2025 22:19:01 +0000 (UTC)
From: "'Mark Brown' via kasan-dev" <kasan-dev@googlegroups.com>
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
 Linux Sound <linux-sound@vger.kernel.org>, 
 Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
 Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@kernel.org>, 
 Pawan Gupta <pawan.kumar.gupta@linux.intel.com>, 
 Jonathan Corbet <corbet@lwn.net>, SeongJae Park <sj@kernel.org>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 David Hildenbrand <david@redhat.com>, 
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, 
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
 Huang Rui <ray.huang@amd.com>, "Gautham R. Shenoy" <gautham.shenoy@amd.com>, 
 Mario Limonciello <mario.limonciello@amd.com>, 
 Perry Yuan <perry.yuan@amd.com>, Jens Axboe <axboe@kernel.dk>, 
 Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
 Andrii Nakryiko <andrii@kernel.org>, 
 Martin KaFai Lau <martin.lau@linux.dev>, 
 Eduard Zingerman <eddyz87@gmail.com>, Song Liu <song@kernel.org>, 
 Yonghong Song <yonghong.song@linux.dev>, 
 John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
 Stanislav Fomichev <sdf@fomichev.me>, Hao Luo <haoluo@google.com>, 
 Jiri Olsa <jolsa@kernel.org>, Dwaipayan Ray <dwaipayanray1@gmail.com>, 
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Joe Perches <joe@perches.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Rob Herring <robh@kernel.org>, Krzysztof Kozlowski <krzk+dt@kernel.org>, 
 Conor Dooley <conor+dt@kernel.org>, Eric Biggers <ebiggers@kernel.org>, 
 tytso@mit.edu, Richard Weinberger <richard@nod.at>, 
 Zhihao Cheng <chengzhihao1@huawei.com>, David Airlie <airlied@gmail.com>, 
 Simona Vetter <simona@ffwll.ch>, 
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, 
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, Ingo Molnar <mingo@redhat.com>, 
 Will Deacon <will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Waiman Long <longman@redhat.com>, "David S. Miller" <davem@davemloft.net>, 
 Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, 
 Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, 
 Shay Agroskin <shayagr@amazon.com>, Arthur Kiyanovski <akiyano@amazon.com>, 
 David Arinzon <darinzon@amazon.com>, Saeed Bishara <saeedb@amazon.com>, 
 Andrew Lunn <andrew@lunn.ch>, Liam Girdwood <lgirdwood@gmail.com>, 
 Jaroslav Kysela <perex@perex.cz>, Takashi Iwai <tiwai@suse.com>, 
 Alexandru Ciobotaru <alcioa@amazon.com>, 
 The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>, 
 Jesper Dangaard Brouer <hawk@kernel.org>, 
 Laurent Pinchart <laurent.pinchart@ideasonboard.com>, 
 Steve French <stfrench@microsoft.com>, 
 Meetakshi Setiya <msetiya@microsoft.com>, 
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
 "Martin K. Petersen" <martin.petersen@oracle.com>, 
 Bart Van Assche <bvanassche@acm.org>, 
 =?utf-8?q?Thomas_Wei=C3=9Fschuh?= <linux@weissschuh.net>, 
 Masahiro Yamada <masahiroy@kernel.org>
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
Subject: Re: (subset) [PATCH 00/14] Internalize www.kernel.org/doc
 cross-reference
Message-Id: <175650594072.395832.3911302052314725751.b4-ty@kernel.org>
Date: Fri, 29 Aug 2025 23:19:00 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.15-dev-a9b2a
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NpneGQ3Q;       spf=pass
 (google.com: domain of broonie@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mark Brown <broonie@kernel.org>
Reply-To: Mark Brown <broonie@kernel.org>
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

On Fri, 29 Aug 2025 14:55:10 +0700, Bagas Sanjaya wrote:
> Cross-references to other docs (so-called internal links) are typically
> done following Documentation/doc-guide/sphinx.rst: either simply
> write the target docs (preferred) or use :doc: or :ref: reST directives
> (for use-cases like having anchor text or cross-referencing sections).
> In some places, however, links to https://www.kernel.org/doc
> are used instead (outgoing, external links), owing inconsistency as
> these requires Internet connection only to see docs that otherwise
> can be accessed locally (after building with ``make htmldocs``).
> 
> [...]

Applied to

   https://git.kernel.org/pub/scm/linux/kernel/git/broonie/sound.git for-next

Thanks!

[12/14] ASoC: doc: Internally link to Writing an ALSA Driver docs
        commit: f522da9ab56c96db8703b2ea0f09be7cdc3bffeb

All being well this means that it will be integrated into the linux-next
tree (usually sometime in the next 24 hours) and sent to Linus during
the next merge window (or sooner if it is a bug fix), however if
problems are discovered then the patch may be dropped or reverted.

You may get further e-mails resulting from automated or manual testing
and review of the tree, please engage with people reporting problems and
send followup patches addressing any issues that are reported if needed.

If any updates are required or you are submitting further changes they
should be sent as incremental updates against current git, existing
patches will not be replaced.

Please add any relevant lists and maintainers to the CCs when replying
to this mail.

Thanks,
Mark

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175650594072.395832.3911302052314725751.b4-ty%40kernel.org.
