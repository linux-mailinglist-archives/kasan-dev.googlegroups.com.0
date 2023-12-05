Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDHQXOVQMGQE2Y6AP2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CF3FF804FFC
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 11:14:37 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-35d5524586csf39424985ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 02:14:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701771276; cv=pass;
        d=google.com; s=arc-20160816;
        b=rZ0QbO1bOikeNMVAKTVCTfrr9nLNiu5a6H9pOdYIP3ItG/95zj0rlomzofGLII+te0
         38UBT2XMoL+fJaPTpDeD+CiBl+syYtfCkpskdaipilC25Bub/xxSIzvLR5UHKFEND/do
         ZryotMcetI6Jkbr2imXQjtVwLXCwUqp5lLDwSa3Tp/Js67PjlaLQLcRtSsvdonavmmdh
         36hJiDxmuctefYZqEf0nCfkpCA5Z+LnSGw9SHpAsFn2B0UIXou7LVR9xcGQRDFxL2+Vy
         kO4R+t0MSZBA0bBXPWK8d4m5LKgR1GEnsizHQ7RYioqUjjGDbFH7v5eccuRPVPYbDckx
         C39Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=7XE38HhFTaouWZ72OT2VgoHOu8T6luKPaKTOL7V/C5g=;
        fh=06sOGDy6+X3nN0awOxb/HH+z4VuvuKLqmFUbQx9UqP4=;
        b=BlARfKMN4CdZZFUqjjY4sdCdz1S3inqbVTIGMkLfq1/jqj0G32jFph5B/WZdPE3EM7
         xyiEx7q28nC2HwWD6Z4MGEGLNubP9HBIuxeF//xXQPWF3k09d0gWmR6Iu8ktjOXCuK36
         jqTynsgfK+LWFpqgy8+/kGTkej296FffOZ2rqw2Ml4m91aimM3yHddwnS/BvzuOvweBP
         8EmPgqWzZUP88IkKPCMImr1opOh/nQ+uZzHNjXncQW+RVhSAZJE6CQJE5HQLEsOD1g0q
         6lrccsOM2saIGIxrSScr6+Q5/VKB8ds8n1sUQ0m/TTaS9STX3yeS/kVaBN7fhI5nQMy5
         U54g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G2QcMBNa;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701771276; x=1702376076; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7XE38HhFTaouWZ72OT2VgoHOu8T6luKPaKTOL7V/C5g=;
        b=Ir4oZ51ufH0ssWRx7GU7tQEuc/GlmZkx8IjpM6GfRlLqCBwt4gacZ4u00sd3wKK/gT
         yBSI8DrkPp5RS9KqI2TeNA/21QZXPiCUFibcW3uZcj92/iI+s3QpZWxwmJGs48Jc+KX2
         jA7L7W6QnmOar/gztT+WmW6GcvBfNPGBWUsOvF4qrpov6thVRhjsi1TkZ3JM9PdUarSI
         r2pzhhlc02CGjwrCaunpKX5F3JLyk65V7XrdE1O1IwN/dMjsx1PMVV1CTrcBJJkO6DXv
         z0k9rcIkV8CYt0QxgCgJ8sF1CXVIqRq5FuIQVmW0lczD7UPqXyaTuhosD6ibzF/31AoS
         bG4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701771276; x=1702376076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7XE38HhFTaouWZ72OT2VgoHOu8T6luKPaKTOL7V/C5g=;
        b=mBsxTIEHz7FivWVZI/W9Rs2p2ARBdwBPafwU4U38L4OWHhRljpHX+E5ak7nukZRdBG
         yvGaftYsrIJVNpafYdr8T7CG97WCqyIGeOz4onvKH5hYu+7/S8RKK165FlmBNvA8hI3Y
         yu/rpkzO+c+BLT1yDfvM+F5s5F1umdpfgXQ0pr3UBXNCmeRfZT4QM8qeoSyfHbm2FHsL
         7WoSje62IVW9OTeRodCgk1zw84q90Y8q3Ck6tBVtv+UCRrKqYJUsaNG4Zv5vJznM+qOL
         ILxt1t1FcF9qgwCyfr98D391r9vCkJeRFC6xpXchZ/EZtWt8MDKHc/tpSAK087gHc/zq
         yC8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzX2L+MLrw3iOYRPj3yFamgoJgnN/HIaieS91qg/OLm6TUCksou
	uoY6e8kgcMkCBYFNp0g2N6w=
X-Google-Smtp-Source: AGHT+IHTTN10RKF+BHqpWuqta1kMoyRDdPt08RhEfrKQ35pzH76XKiy8e/bTqmzKYrKBVdpARF3eaQ==
X-Received: by 2002:a05:6e02:2607:b0:35d:7411:3294 with SMTP id by7-20020a056e02260700b0035d74113294mr3323966ilb.7.1701771276566;
        Tue, 05 Dec 2023 02:14:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:219e:b0:351:61f9:f7bb with SMTP id
 j30-20020a056e02219e00b0035161f9f7bbls3317077ila.2.-pod-prod-07-us; Tue, 05
 Dec 2023 02:14:36 -0800 (PST)
X-Received: by 2002:a6b:d20d:0:b0:7b4:28e4:8509 with SMTP id q13-20020a6bd20d000000b007b428e48509mr5406224iob.11.1701771275525;
        Tue, 05 Dec 2023 02:14:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701771275; cv=none;
        d=google.com; s=arc-20160816;
        b=JZJq/ZtWxLFqLfUl/tCSFOZnOChMjvrfYnhDPS+xV61XcmxlnPpr8ESFD52fB1ItWZ
         a3bu1eFMV3wz9Nhk/EZpL2lGUTFMJOkqBEJ01wTt3usszXkpfwm+D6XWOo+6RY53ubEp
         XuPNW8Yc3bppFPAt5V8Ui8J6fFzjP4yAVnJHfPCd2VefDgZ5h+/fBP16fZOOAFbsGFr+
         I0SG6dXCjdg8cWBl9DeLm0t7Svr28LX5K3bSPzNnuszkMt8BCgtGPf/8tahLuOtUf6kn
         zMI55nnr3/HP/+S23777NPg2uaAbABn6aY5rD1spJhbsuG43cp2NnT4mi2R274xiLT+S
         jn9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=bhZrWsCVSRl3/gNFhL1HvzTeirgk1o9QDebzo7iN2f0=;
        fh=06sOGDy6+X3nN0awOxb/HH+z4VuvuKLqmFUbQx9UqP4=;
        b=r4NS1Pi6qq53KoCzskwIv90dKB6C3b8RSwPonP20meQ4E802A6IYml/51fko10aOSF
         2dK8fk+rxaidQ2HpUQQxuG0z6tKniJWBz6Q30kA3BB3/I1IODkkg7DlOz6W8PFcvXO1z
         yrKwQcu2MuU3K4hvcXbTHZyCSB22RIx6U1gjC4t1Vg/PGsxa208TggJDuqIZ11fHBUad
         uLAEwRQQR98nTDSB1UIqdxsotQdcfFY/VLWSgWzeQ+tgyLdYGj5weHZQlZmNXIIW2Ijc
         ZmKfuUA7sTMfmdVnYxGB/WsHRjm4OrPfkcljk7Y+MTAnNOpuakxZYbnQjfJcAEXgMrJu
         DzYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G2QcMBNa;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id e16-20020a02a790000000b004667fd6f6besi767526jaj.5.2023.12.05.02.14.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 02:14:35 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 735DE1FB8B;
	Tue,  5 Dec 2023 10:14:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 45C35136CF;
	Tue,  5 Dec 2023 10:14:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tYCWEAn4bmWAZwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 05 Dec 2023 10:14:33 +0000
Message-ID: <93a8a67c-9cb7-0d36-6b14-ce15a30bea3f@suse.cz>
Date: Tue, 5 Dec 2023 11:14:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH v2 02/21] mm/slab: remove CONFIG_SLAB from all Kconfig and
 Makefile
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-2-9c9c70177183@suse.cz>
 <ZW6j6aTpuJF0keS7@localhost.localdomain>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <ZW6j6aTpuJF0keS7@localhost.localdomain>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spam-Score: -2.60
X-Spamd-Result: default: False [-2.60 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_HAM(-3.00)[99.99%];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FREEMAIL_TO(0.00)[gmail.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com,cmpxchg.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=G2QcMBNa;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/5/23 05:15, Hyeonggon Yoo wrote:
> On Mon, Nov 20, 2023 at 07:34:13PM +0100, Vlastimil Babka wrote:
>=20
> Looks good to me,
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks.

> Nit:
>=20
> - Some arch configs enables DEBUG_SLAB
> - Some documentations refers to {DEBUG_,}SLAB config (i.e. "enable
> DEBUG_SLAB for debugging", or "use SLUB instead of SLAB for reducing OS
> jitter", ... etc)
> - fs/orangefs/orangefs-kernel.h uses #if (defined CONFIG_DEBUG_SLAB)
>=20
> $ git grep DEBUG_SLAB arch/
> arch/arm/configs/ep93xx_defconfig:CONFIG_DEBUG_SLAB=3Dy
> arch/arm/configs/tegra_defconfig:CONFIG_DEBUG_SLAB=3Dy
> arch/microblaze/configs/mmu_defconfig:CONFIG_DEBUG_SLAB=3Dy
>=20
> $ git grep SLAB Documentation/
>=20
> [... some unrelated lines removed ...]

Yep, I've wrote in the cover letter that to keep the series reasonable and
limit Ccing other subsystems on some patches, not everything is cleaned up
thoroughly, and is left for further work (some already started coming in
from others) that can be submitted to relevant subsystems.

> Documentation/admin-guide/cgroup-v1/cpusets.rst:PFA_SPREAD_SLAB, and appr=
opriately marked slab caches will allocate
> Documentation/admin-guide/cgroup-v1/memory.rst:  pages allocated by the S=
LAB or SLUB allocator are tracked. A copy
> Documentation/admin-guide/kernel-per-CPU-kthreads.rst:          CONFIG_SL=
AB=3Dy, thus avoiding the slab allocator's periodic
> Documentation/admin-guide/mm/pagemap.rst:   The page is managed by the SL=
AB/SLUB kernel memory allocator.
> Documentation/dev-tools/kasan.rst:For slab, both software KASAN modes sup=
port SLUB and SLAB allocators, while
> Documentation/dev-tools/kfence.rst:of the sample interval, the next alloc=
ation through the main allocator (SLAB or
> Documentation/mm/slub.rst:The basic philosophy of SLUB is very different =
from SLAB. SLAB
> Documentation/mm/slub.rst:                      Sorry SLAB legacy issues)
> Documentation/process/4.Coding.rst: - DEBUG_SLAB can find a variety of me=
mory allocation and use errors; it
> Documentation/process/submit-checklist.rst:    ``CONFIG_DEBUG_SLAB``, ``C=
ONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> Documentation/scsi/ChangeLog.lpfc:        CONFIG_DEBUG_SLAB set).
> Documentation/translations/it_IT/process/4.Coding.rst: - DEBUG_SLAB pu=C3=
=B2 trovare svariati errori di uso e di allocazione di memoria;
> Documentation/translations/it_IT/process/submit-checklist.rst:    ``CONFI=
G_DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> Documentation/translations/ja_JP/SubmitChecklist:12: CONFIG_PREEMPT, CONF=
IG_DEBUG_PREEMPT, CONFIG_DEBUG_SLAB,
> Documentation/translations/zh_CN/dev-tools/kasan.rst:=E5=AF=B9=E4=BA=8Esl=
ab=EF=BC=8C=E4=B8=A4=E7=A7=8D=E8=BD=AF=E4=BB=B6KASAN=E6=A8=A1=E5=BC=8F=E9=
=83=BD=E6=94=AF=E6=8C=81SLUB=E5=92=8CSLAB=E5=88=86=E9=85=8D=E5=99=A8=EF=BC=
=8C=E8=80=8C=E5=9F=BA=E4=BA=8E=E7=A1=AC=E4=BB=B6=E6=A0=87=E7=AD=BE=E7=9A=84
> Documentation/translations/zh_CN/process/4.Coding.rst: - DEBUG_SLAB =E5=
=8F=AF=E4=BB=A5=E5=8F=91=E7=8E=B0=E5=90=84=E7=A7=8D=E5=86=85=E5=AD=98=E5=88=
=86=E9=85=8D=E5=92=8C=E4=BD=BF=E7=94=A8=E9=94=99=E8=AF=AF=EF=BC=9B=E5=AE=83=
=E5=BA=94=E8=AF=A5=E7=94=A8=E4=BA=8E=E5=A4=A7=E5=A4=9A=E6=95=B0=E5=BC=80=E5=
=8F=91=E5=86=85=E6=A0=B8=E3=80=82
> Documentation/translations/zh_CN/process/submit-checklist.rst:    ``CONFI=
G_DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> Documentation/translations/zh_TW/dev-tools/kasan.rst:=E5=B0=8D=E6=96=BCsl=
ab=EF=BC=8C=E5=85=A9=E7=A8=AE=E8=BB=9F=E4=BB=B6KASAN=E6=A8=A1=E5=BC=8F=E9=
=83=BD=E6=94=AF=E6=8C=81SLUB=E5=92=8CSLAB=E5=88=86=E9=85=8D=E5=99=A8=EF=BC=
=8C=E8=80=8C=E5=9F=BA=E6=96=BC=E7=A1=AC=E4=BB=B6=E6=A8=99=E7=B1=A4=E7=9A=84
> Documentation/translations/zh_TW/process/4.Coding.rst: - DEBUG_SLAB =E5=
=8F=AF=E4=BB=A5=E7=99=BC=E7=8F=BE=E5=90=84=E7=A8=AE=E5=85=A7=E5=AD=98=E5=88=
=86=E9=85=8D=E5=92=8C=E4=BD=BF=E7=94=A8=E9=8C=AF=E8=AA=A4=EF=BC=9B=E5=AE=83=
=E6=87=89=E8=A9=B2=E7=94=A8=E6=96=BC=E5=A4=A7=E5=A4=9A=E6=95=B8=E9=96=8B=E7=
=99=BC=E5=85=A7=E6=A0=B8=E3=80=82
> Documentation/translations/zh_TW/process/submit-checklist.rst:    ``CONFI=
G_DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
>=20
> --
> Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/93a8a67c-9cb7-0d36-6b14-ce15a30bea3f%40suse.cz.
