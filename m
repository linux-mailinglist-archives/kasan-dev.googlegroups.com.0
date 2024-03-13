Return-Path: <kasan-dev+bncBDXYDPH3S4OBBH7TY2XQMGQE4XFHJ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C9E987A985
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 15:35:12 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-412dc43e33fsf1005285e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 07:35:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710340511; cv=pass;
        d=google.com; s=arc-20160816;
        b=rZEsZwHUw+90XZT89XEun63C/SS+a70sC+Kwbm9ALyLVTZh536das3ggO2Fu3NCXnJ
         7+a+ZeaadwZ3hStjv+sia12fD7oRgLVW+W3z0/2V/LHNa2C86mghmI8cuGU86piavXZ5
         7ITiTIRxvlhRbjzTtRbxKMIdPBuyf5L1QUcGUKtQ5BUTQ2M0VTSxStd2WjwAFPE4tf+6
         hc1CV9mCkXoNs5A+PIBKckMS2/pLLWdafixWdpjJkNwCTrOzEuD108OaYIf3X43gzDkY
         RZcX+GccKZ+EYUlsmj5WTygUpXqA+S+WYIQx35QxBhDb3sTjSMzkni/pDtnswU8n7GSE
         /cMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=HIphuLYGYwvd6ZtLKUyHmEbR/GB2nWTeJ6OSxjNctRU=;
        fh=0QqBzw7vzTMT/AF/2bKH5QWibwyua9cffX7nREQdkFo=;
        b=z0ZP5CoAMus2w12H1iidN62YUNjCQLpv+Ddn6sn5834br1axsfXXGQF/J3/QGteFOO
         abkgcYJ3XdFRX84b7kT86fY3RwmaEvG2kqI/Xw4lK+UhO//wWHdsIkgLw80Oel4tgvlD
         +msrk9qoLCVKMtV/fXC27joWtPpo7u6t/rrHdfLW5H2DmybrBeebtfiRZHzHpx6m6UqG
         n93vRhTsWeAtPv8rSZgamSk07UbkvsU70xC/LvqL9Hiif8WWa6UEwte2rQ1a4chHHXAB
         WUYmeaq+30B/wTC97C0khDgAmtgb9FiNFCMyIP6cIllc0Rjw38Uzs9G3c3Nt3nZ16iCr
         Z20w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ebqOZkqA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="YR/kwdkQ";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710340511; x=1710945311; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HIphuLYGYwvd6ZtLKUyHmEbR/GB2nWTeJ6OSxjNctRU=;
        b=Vuh+8igJGyYVY/RMfvyNs+GZ+6FcjhbWkDwyId6RLIr3efDLXn7HXjuSMNy2JkgDia
         pi6dFGM8xiaGTaSLVFHT6OjJR6vy5ATioxtar4EE+bKqf9KGiV0voBSsKODl1fuz1v4/
         WsL8oflJPRf1iPfN9rFA89YTJakyc8UMPnSePss71LEN/XrJ2MUcD7Y/0DZp+WX24pHg
         +2AoccGVmeKldDBUqLcfcZIXmyGUPwPz8W3aCjtNo3/Z+n3sSD0CIrlKvklmHq3pLFFP
         co9XsXFdvzINIVsEEwbRv9QoWWKq7+jLZmdbTFSzTZY9gYAe3c42l9SvLgrfk6xKDrFG
         AXJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710340511; x=1710945311;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HIphuLYGYwvd6ZtLKUyHmEbR/GB2nWTeJ6OSxjNctRU=;
        b=kY97+Uv/fWRrclaNA5kig7DlJ5/5sH0OGuMDybVbzLr2dncFn7DiAfr9qscjTJv31C
         qsVHzvj5FZUDjUdzcpYhGpZVhoxmE2SbWwbFBZBHbYlPBC8Kf5i1W/JRu5tmuh/EX62E
         MlZWfbu1n1L8hM13aoZoC7vs7zOS+Tc+bVVNGXsdouAjZJcej7ocDxuPSaeHCPoTo4pA
         9buGoF7ksbJ8FQa/WpgZ0vMYDm0J7jfiQIyc+J96fpf//8XFu91/TFQGumXeQl2MH6t6
         AZE+GrhO2dUXFuR8+8SP8Fw9W/ckk239GxiXC1gNBx0DRPdsS1M2vJrQiPjMeMd9fxe1
         H+UA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrnFo3I8as4ByROEJ2yN9e3c8uLMuP+x4tiZnXQ9jCPPmSwRv2kpEBLLZkYutH3qyZFF+tdlIlc0OEd+X6Sph6YbVd2KIT9Q==
X-Gm-Message-State: AOJu0YxlStyuOf37epheHt36iBpnqqysCR8IlYKlYhyI9eJtMfnbevAI
	Vyi85DHGn1RIzld1xaBxBy0SKlNBlAeEuM2ccdyVkiTpn7Vf+APM
X-Google-Smtp-Source: AGHT+IF2ssQcl7fv6/EcBmabim3TXsrNIxkOFfbUNKd4pYf9CSRFqP5AztZMc4QTC9UnYQzKaTc3HQ==
X-Received: by 2002:a05:600c:1da1:b0:413:eae8:4452 with SMTP id p33-20020a05600c1da100b00413eae84452mr92758wms.5.1710340511323;
        Wed, 13 Mar 2024 07:35:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b20:b0:412:f016:60dd with SMTP id
 m32-20020a05600c3b2000b00412f01660ddls554318wms.1.-pod-prod-03-eu; Wed, 13
 Mar 2024 07:35:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqHEZSvBa25Of5Dk1+xoKXtMY3K0c9Kd/Qg6Iom3zOckqsN4V1jQQt1qmV2/Lem1LGv4B01TGz57MBhrmQHrn0zj7gjbeG8TArtg==
X-Received: by 2002:a05:600c:45c9:b0:412:c7d9:bd96 with SMTP id s9-20020a05600c45c900b00412c7d9bd96mr130651wmo.8.1710340509522;
        Wed, 13 Mar 2024 07:35:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710340509; cv=none;
        d=google.com; s=arc-20160816;
        b=FAIW+OUFMjhb9uqQA7EjFCnBkjzukWIGoiOU0dbFEmQBwVV56lznQJoUmO/ZrxxqyQ
         GW/TscE9z/qTFiqrNc80oAA0JdRdi7upwU6IaR0rFJLqNdv+Z4HIAw9useKBQZJ68IpJ
         H+HXE/s2P/kpELstsVMOsuN5rzFUEaBxUc6jPX6Lmmu/arTgmKwqylaYaQl/JM3p96P6
         sak+1VbTcQjZ+G1SnMvnF8unBdnWB6omhgE/dQS3wpHQoYgXn+fWbAc8RSzmt3t7TypX
         6jdVaplbzG/g8iaq955Tpm7iHT2/ACKtXBGBGW3111CqiYs/DXwcUIbKd6OQYBslv0il
         rREQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=2RSlYwqGCgMw8Oen4eBYJ9RLkQu5lewBFTm9qigzA78=;
        fh=T/slm/RCgVOv9Z2m2Kuiq5NwRE9Ne3JjQWJHIJg2CLI=;
        b=v4t/Cq5aaApkeK9MusF85CDWCgYMQdKJuTRf3EyicDFSngs9ipLvYJNTO/oOpnVnzU
         cGzp1tUFIeZlTeMOXdLoyYTcG+d2CtGKnVBkJp55HflMZ0V9nixThHMyTI7Mv32yKv1d
         bK5Lb2Mqz+/b+qUiTZW7aj/9DztOqvlv4exMN/V2/UlioYp6RgstUAZpdLnwjXHt4C38
         dnaBPYH1maybkBYLPdLT7wZjbH8vMSMRugNIVR2I/ft+0abrYH5F2kBQE5qC7C1jA89d
         lBEruLl1LH7ABSTWzDMjpebWInNtiVXsjAC+I2HjlUBlODZZNab0Nx0QNygGs5meBJnt
         rskA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ebqOZkqA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="YR/kwdkQ";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id p13-20020a05600c1d8d00b00413ee3720dbsi23141wms.2.2024.03.13.07.35.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Mar 2024 07:35:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D7E1A1F7D5;
	Wed, 13 Mar 2024 14:35:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8145F13977;
	Wed, 13 Mar 2024 14:35:08 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id WfP0Hpy58WX6YwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 13 Mar 2024 14:35:08 +0000
Message-ID: <ef836dd3-0b65-485e-84a2-dd5cb9ecdff1@suse.cz>
Date: Wed, 13 Mar 2024 15:35:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 15/37] lib: introduce early boot parameter to avoid
 page_ext memory overhead
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-16-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240306182440.2003814-16-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.79
X-Spamd-Result: default: False [-2.79 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[75];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,nvidia.com,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ebqOZkqA;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="YR/kwdkQ";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/6/24 19:24, Suren Baghdasaryan wrote:
> The highest memory overhead from memory allocation profiling comes from
> page_ext objects. This overhead exists even if the feature is disabled
> but compiled-in. To avoid it, introduce an early boot parameter that
> prevents page_ext object creation. The new boot parameter is a tri-state
> with possible values of 0|1|never. When it is set to "never" the
> memory allocation profiling support is disabled, and overhead is minimized
> (currently no page_ext objects are allocated, in the future more overhead
> might be eliminated). As a result we also lose ability to enable memory
> allocation profiling at runtime (because there is no space to store
> alloctag references). Runtime sysctrl becomes read-only if the early boot
> parameter was set to "never". Note that the default value of this boot
> parameter depends on the CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> configuration. When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n
> the boot parameter is set to "never", therefore eliminating any overhead.
> CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y results in boot parameter
> being set to 1 (enabled). This allows distributions to avoid any overhead
> by setting CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n config and
> with no changes to the kernel command line.
> We reuse sysctl.vm.mem_profiling boot parameter name in order to avoid
> introducing yet another control. This change turns it into a tri-state
> early boot parameter.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ef836dd3-0b65-485e-84a2-dd5cb9ecdff1%40suse.cz.
