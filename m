Return-Path: <kasan-dev+bncBAABBRPN33CQMGQEGC2CPBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DCD1B412F4
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 05:32:23 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70fa9206690sf9412536d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 20:32:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756870342; cv=pass;
        d=google.com; s=arc-20240605;
        b=kIj6sKdZwP35ZGKmfxygIRR77bZ7CiBszNM3Qo4bEJCVOycMPOVRIvcvEJQnlCEq5q
         vZl4r90Z5dhvDx/KEQfW/nxdk7m51EgpVgsDQMO5OhomrOXdTYWYe+VT+z7Z8zGC99pI
         pz9kCmLXOZn+Z2DDV6vZ5zGhg+Qnu1YJuIYa7UeaqZtPZCOmOdEpl9Yf4KnbGCarUvyZ
         iNQLNZU55bW9G4YEEtIw5Hm6WxDMPudVpff3ObtDtMhn/992KXZf0zvFFtoaDBqB7j8O
         0EAXjs/ClqfDqmRjcahV2zGY76MRiD55aPIsJzuUILL0nDPruDBvlRDrusJbZ/t8PYNU
         wzXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=9zornXC5P0PiOmBk2COLA+KLzC5IeoNfGA1dGT5jnj4=;
        fh=J/82tPu5JczgI2ELrm8629jBNWb6KiXto+ouy6G/0w4=;
        b=QDDzyeopR4KQ1K/Q6lfS/c++wKxztSah70AhdYLXIZUDZdnlm+f/dDdG68zEpghGPB
         9VVGzUy543nhWJrXOG/DWvKclPZxE6kHkTcU+tM6MXBjZbxDyvtcApsmiLf4HhorVz40
         XKwLZtMOknywsOoaJ1Fo7x+aVLu0WAKadlD0Sl0CY2ibuJR1lZAQpkQTG8yljIw8l6MS
         XWYIUMsYWVB7fJ7yKAn+/tslyY8EFpdQrNuyxfCuiUsDi27t7UG+oXkow2K8lObkcqWL
         Xlq/dDOaEaT61cKaU1jiUWDi1AOrdm0a/pLTefENEnlCDEpaI8BuegZ3re5ccGAL10v/
         eA0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="c6/aA16+";
       spf=pass (google.com: domain of superm1@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=superm1@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756870342; x=1757475142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9zornXC5P0PiOmBk2COLA+KLzC5IeoNfGA1dGT5jnj4=;
        b=TjzXpVsu7H3B+/i7OVqGICD8NObSyPRdykTITr47876LudtiqWOMvkf5MUiaJ/xyyc
         CTHFzhP+ujJtvqFrxGxaibWIKoCeYBfCaffDsbOJDTMpsQkVVIEr8jmvzf2nPPs1Kpku
         sSuiOHBfCMgkcCQMLzuCQZu8KLeKcdhls0f6kc5uzvtIodvJnJ/QDHN4Hlblklg0QlmK
         Abn+3Jjh7DQHi/iI0nmGw+5RDe1wkgKYSGUsVG0kvIa/eR/9ciG18S1up1U7XmkTDce7
         UCAfN1iq8j7DEmXBHNiJqcoVTREIdb4vbVNtgcHWKuIBatz1vW124PR5e2kBBNT7bi1m
         C+vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756870342; x=1757475142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9zornXC5P0PiOmBk2COLA+KLzC5IeoNfGA1dGT5jnj4=;
        b=DWo1Zn93xoChEoAZiERsJ0Sw73ZKCUEvbFVSqcbjqJF+diXKFS09S1lXPpQ9BzU711
         Cl1KB+FMsoPNXyYmyIxiXm7tdr7lVdQYnhhLMjE10mas4v8Va9xBiwd2WXvE1a/DWQwn
         2hT6coyp6y7HvcxlKhYH2JQGgMWX/Xi/F7Kr2L5F1u0WSShMpMbp76nYALMZkhugC5L8
         ZnTXohtHM8hxK8uFm8kkAdchlkL1kRhuF5BwgI6RLNNu3o+sMbsGJKFmWPm7GCYp/FoT
         Jdj25bUHcvU+JHlBng47yT0dxDYAv2L6puLPOoxnUKdssOAk6esFlR4iNJ6IJJ7buEIE
         H3Ow==
X-Forwarded-Encrypted: i=2; AJvYcCXnSHgLG9p8a/YJEi7h1HxSLR6u58o7a1bTZwUUD5vTxAwdMJlBBP+tTH4knWV986oJHxx3xg==@lfdr.de
X-Gm-Message-State: AOJu0YxNnD6lZoOpFeuoYjT7iicl623b+TpXvvllrNCZvSK2lYnasCRk
	7qN4cyKZihbavVkrFFtuQpNxAxUCGo5Re5Xd/QAcuzPlbgY86Vxsdhk/
X-Google-Smtp-Source: AGHT+IE7EFINFW659TISAnWz3yR6wO9Pf0bJ74z6JrCCun8ASOTL9p+7Wx+kPIS89CpzGhl6S2bhow==
X-Received: by 2002:a05:622a:19a5:b0:4b3:e96f:c1ce with SMTP id d75a77b69052e-4b3e96fdc4emr36565941cf.27.1756870341973;
        Tue, 02 Sep 2025 20:32:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfD3c5Vo7UfYDDA2uqJDoxFnI7vg5AEVfmGkWqG+whVDA==
Received: by 2002:a05:622a:180a:b0:4b2:d25a:141e with SMTP id
 d75a77b69052e-4b2fe856655ls62155011cf.1.-pod-prod-00-us; Tue, 02 Sep 2025
 20:32:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4b9VMiL6j1bk9E1PiivQOpSzpkuMfjr7Sws0BQWSzsG0+2JbMALIj3W7KKFAdoJ8OOAhPGz0HVUw=@googlegroups.com
X-Received: by 2002:a05:622a:102:b0:4ab:7a27:ec59 with SMTP id d75a77b69052e-4b31b98c98amr171505611cf.19.1756870341238;
        Tue, 02 Sep 2025 20:32:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756870341; cv=none;
        d=google.com; s=arc-20240605;
        b=G6T0T6joSD12DQXZstrwkybuYUjAADqUoCrTQKALLpV4eXJt2EjbAUfDheAskH3wIL
         GLBp0DfRwI0Xual+zOjb/2JHc4p4BO8V0kBXw5Z+eqcuLYXgsdw4ptZ+HnG5++cVoTBg
         ctggF3RUWDjE8RaT+5eP5P52dygq+MSIDsAG117VxHYbUlC1DOZt98ozFxynYGHSJBMA
         C//sAN+L0FhhwBk902WjR0O2kBiqvH1h58+wfKejs9ZtDl6sag0+scQ1v4vejfnR4EIe
         GQOQbPZgPcz7jb88C7IH7al9D1IPwqYIax44SP/rzERQT67KASiuYllaR58ZVb50952B
         79PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=rWhJThhT6wJhyT9aykv2T89JLmY/pZ9Lzvy+TuJsbAE=;
        fh=z5ngTkVlOxYa6BqdAuqJENo1JKYfhOLdWfrt8m+KRd4=;
        b=CWTBLmErCtBMl5yrr2WJJ0GVMNqvQhhnRQoU5gOoJuVfHallek4DWgObuxpiOGEedF
         KAuyJ9EwnM9zXwYwgcCVjuCEtPZpF8eucjjcHTnxkhYPP7KfoNvr0msIEECGkN+1XOHM
         z983JdBwYqYW3W79Qx8GuAC5rwye3FXk6LHpafC7TDOTZqqszHWGNk9LzF1i8Tq9GjjD
         ZSYihIoTtsCutHmM9xSNc7c98grh1R4UY6FcBffs/tekKEdRLZwaYqaC+Gw4R+DsQcAk
         +dkOMEYbnBXePZNuGdAO4XOeazIvJ/KxKyongRXCF1E6V3lBpIfTqW0inJgiehHEbQaH
         4hpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="c6/aA16+";
       spf=pass (google.com: domain of superm1@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=superm1@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f657ae2si425611cf.2.2025.09.02.20.32.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 20:32:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of superm1@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 73A156013B;
	Wed,  3 Sep 2025 03:32:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C22F8C4CEF0;
	Wed,  3 Sep 2025 03:32:08 +0000 (UTC)
Message-ID: <3242f4a2-9a5f-4165-8d24-5c2387967277@kernel.org>
Date: Tue, 2 Sep 2025 22:32:05 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 04/14] Documentation: amd-pstate: Use internal link to
 kselftest
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
 <20250829075524.45635-5-bagasdotme@gmail.com>
Content-Language: en-US
From: "'Mario Limonciello' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250829075524.45635-5-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: superm1@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="c6/aA16+";       spf=pass
 (google.com: domain of superm1@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=superm1@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mario Limonciello <superm1@kernel.org>
Reply-To: Mario Limonciello <superm1@kernel.org>
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

On 8/29/2025 2:55 AM, Bagas Sanjaya wrote:
> Convert kselftest docs link to internal cross-reference.
> 
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>   Documentation/admin-guide/pm/amd-pstate.rst | 3 +--
>   1 file changed, 1 insertion(+), 2 deletions(-)
> 
> diff --git a/Documentation/admin-guide/pm/amd-pstate.rst b/Documentation/admin-guide/pm/amd-pstate.rst
> index e1771f2225d5f0..37082f2493a7c1 100644
> --- a/Documentation/admin-guide/pm/amd-pstate.rst
> +++ b/Documentation/admin-guide/pm/amd-pstate.rst
> @@ -798,5 +798,4 @@ Reference
>   .. [3] Processor Programming Reference (PPR) for AMD Family 19h Model 51h, Revision A1 Processors
>          https://www.amd.com/system/files/TechDocs/56569-A1-PUB.zip
>   
> -.. [4] Linux Kernel Selftests,
> -       https://www.kernel.org/doc/html/latest/dev-tools/kselftest.html
> +.. [4] Documentation/dev-tools/kselftest.rst

Acked-by: Mario Limonciello (AMD) <superm1@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3242f4a2-9a5f-4165-8d24-5c2387967277%40kernel.org.
