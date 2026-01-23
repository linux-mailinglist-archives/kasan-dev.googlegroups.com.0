Return-Path: <kasan-dev+bncBCUY5FXDWACRBCXRZ3FQMGQED73RDFQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UF7cLoy4c2n/yAAAu9opvQ
	(envelope-from <kasan-dev+bncBCUY5FXDWACRBCXRZ3FQMGQED73RDFQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 19:06:04 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 33B3B79589
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 19:06:04 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-65821c9e5b7sf2418026a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 10:06:04 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769191563; cv=pass;
        d=google.com; s=arc-20240605;
        b=jAgGado9L5h8GZSeU2pM3BcvEseTesOD3hwhcUbkcNhNqocW0n0Zqjw0uQLc+pR86H
         7z4+25HJaAtGn9QX3zRf/FbQn7DdwJIhiRzLwNt9rQ+zuDqdZgBu0KYrXX+NLDRCrTY6
         XHZ8YkOOqQCmdlk+wAg0IupzL+LLAZuQV2nFNrmJxD6WvZmxe5uMSzL6Y/vvU9pMRHEw
         DEitISBQL6zqLYbO5wxmpynazxZ6HObeIxh4Fbt3KSpzKHJ+pCQeZXHFE/lfTh4UT42C
         ogjb+HJsyCiQaWrrNzYhpehT42mBI8jkExH9mlQulbDExW4un79jdb0Nmv4CxMYIF4v6
         wHig==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MjZhqSrGxzfxo6RsqGSy4q+4gryP0h5kvxL0GnB0KbU=;
        fh=3oEVP5o/lcrC+dXcMtUh8FiUmnHtb8tLWMBv2BVowr0=;
        b=hBpLKU7Z5ghHN9p+qNhcECT/Kg+e8unMN3TNjGqvUEJsbb1MZFZtsGAKuu57t2nXmW
         UI1I5wvmgda9grcWkMGJoTPAK14Dqg80ij4cVPosT1fr/Hg2VpAXDkxu/ub5t7UxN72R
         S9RfJbbtSfE8qnkqiPXBy+24PWWBT+3k1KcNYFwW5vXv0svTsRdKaZNKkwQefODVA+hq
         oBajiiT2gD/Aosb5g6WANiNpbse/hdzIOmvVdVTZ1r6jooyMFCT+ULoWdcrrbF/WLD8Y
         VHNZIUBxg4/iUfzchVqnmnDFVopkWSdfmIRm3SS5lYq8TPY5fM59JwdUQyk5UD9Xiz1Z
         t3mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PKjLi1AC;
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769191563; x=1769796363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MjZhqSrGxzfxo6RsqGSy4q+4gryP0h5kvxL0GnB0KbU=;
        b=OyAxDKd8TfCWf6zCPuVnl+1YzRx+hOemno+OuDrYLd6mZLTtPL2Y2+wR9SR1Q/SAWB
         P5V3NiZLGwEimoY+iu2KV8aF2CRbkOVvJ0yZNFPjPrdCZxI0xpaLP6DKFcHV64KXtYAd
         Le/a7pgKrqH2F9N2YTq7QXLu1eosvHdhwSSeR3zvQ8aaaI2AyPSzJibxrSLHgUKN438M
         3+L8nr9oBCGcEGktGDFZSRn7LnTrXgvZWRrPmq9cRwZwKUG05H6L5MpIvq4ihgFj1r6h
         pgki4oPnjRPSDas2aULfK+YV+ou1WfkkS0BmH+XpdsI0kvGeKFsKx4QTW6iILLUE8XZL
         bOUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769191563; x=1769796363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MjZhqSrGxzfxo6RsqGSy4q+4gryP0h5kvxL0GnB0KbU=;
        b=B2vX76Xd2Drz38FcqVFGxV2YLFNfwGyxhyaTu56SSSH4J5cFi04IubI4Iv0LJgwzyE
         S29pru+Po2MachY6FAnB82Z2/nlIMP/w+FqcqwTK3Rb/uZpx4fZ+DejQM6d16ZTdIszC
         TYAnjor/WeYOCoy5cVg/Saw6sfreSJVquJ59/8dJfkEGFgscOcASKEBC28fZBp/XvmiM
         dUQhV9yAr2l+vwhwhHEnf8z8RlGtMRwMBQrZKmfgtnm7Yo5jfxKYKiGYS1HFukCPlWka
         fY841b+hWzisanRtTcLH3tY6NHqZCGcnatCPw0HmCiRwsNF47kmh3/OTo28keHV0fbD/
         QHyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769191563; x=1769796363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MjZhqSrGxzfxo6RsqGSy4q+4gryP0h5kvxL0GnB0KbU=;
        b=AvZYExEkoYidVVSTTlLAL0eRsOZAG5VxCimJ4yhJRY0JtU6+YuVmXylvg1nzcsbeWA
         G6VAK8CTsdDQt+5h5OgYmj+Cn+CckFw2P3fkL3lwcJJJ+0Fz8u00arRJCsWmkRzD18l7
         A812Vq0r+Too27Qd6hdMvP1v3atwhUKjz8tqLpKMIbfnHO2zw194YLEHrnh+SEylEt0V
         +DDvpDnYrp0YJY3Tnvkkq3k+YZqlW7EoZUarS/JB5ooDnJPU1DMrcDy6UVOiaJTc3qts
         whOakjoph4vovwYc57HGhho0eFvqRibDnpOhdmlVucZOomGqI1Bu2BwubyP/yGHlXHaZ
         wJcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVkN5uS4CLsQrqhRKCX/mIomjCDdd0jnBAzyUG34Ct7d7Dz83P/RCiAFGy5VezgeEpBrhSVTw==@lfdr.de
X-Gm-Message-State: AOJu0Yz9PUYdYcqWy3zumd5eNGSkH9PqMCxdGcVO3yYgDlRM+EPHvI4P
	4vkWQjqI0FYu5aqG10ZY+7qpNp5qwlCXjhWfFZ7ehRwz2uhXDQddrd1a
X-Received: by 2002:a05:6402:5256:b0:658:1eee:8a4a with SMTP id 4fb4d7f45d1cf-65848763750mr2530151a12.11.1769191563243;
        Fri, 23 Jan 2026 10:06:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FH+S9Kqz8VZR60YVgVU7E0HH8KG30G6U/KTkacYH2y1A=="
Received: by 2002:aa7:df14:0:b0:64b:a8b0:ba67 with SMTP id 4fb4d7f45d1cf-658329fb890ls1768435a12.0.-pod-prod-07-eu;
 Fri, 23 Jan 2026 10:06:01 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCURz9Z+nWNZp2TEM5eGUhMp4Ar1csPYMvf/fecQBau7BV3B7mINX9cweBrurTVswwqMaTSAdjc9XJo=@googlegroups.com
X-Received: by 2002:a05:6402:268f:b0:64d:88c:c2ca with SMTP id 4fb4d7f45d1cf-658487b1b1bmr2946393a12.28.1769191560772;
        Fri, 23 Jan 2026 10:06:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769191560; cv=pass;
        d=google.com; s=arc-20240605;
        b=VWwBH/kXD1tBPQzv+jAo/mIiM8CRF2DebJNQIpkxXNHNu54IVcADecWkVYGeYxU+KN
         pC/j9fUVMyjoevH/jxqTp6tbkyekTAZ9p1RlU3lsIBAZrVcedmh1x8YEngfwdfVLRD9S
         gCwPQTJgM2pwxjTBeIY2uKmWfazuSj28d+4SR/HiAgkGLh17apJopNPkZaL13j6FZq12
         wPteISu8ahQ13KLpDQqKZh2IyjBvjk7/E9TEVhcttNc2UD2sGnYO+2RRtz8XlHCRRhjg
         6KpWZ1wC1/f4qHNfXGdSs5OsuU2RCftnRjGCoc091y6FVP9WKWGGnUc6POjOjC4hZKqB
         m8QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FcLGkCfuB/sIPTdRBcsJjPn4bR/XfGlb046z63lGRwk=;
        fh=YMKnLtAwBreUQ9rGYGNb7iKiL49tXFKwKVtbw+jb3mo=;
        b=K6nrgL/A+Yqh4/3GVZsP5gQXWELblqKxsjVF2mUM8fFHtudm0+50sjL3aiKYID/EtZ
         05a9rNCL6m+x2uEjyuW+jZWqOE2h0AHzNJhbUuEHSw+qlQNSJtNHWPh7yq206D755MAL
         SS8htSPURo0eXFwF2X1ES4En/o4Reh9d1I4I6mGMDYgdwJ7mGGAnXp/mp36X3k3iHPbN
         JPtk5jRBVSVaQPeCzoa3bldH/mT4V/e0rbYa+ueZH+nzugjsh33+rNFeDGJZpQPq8IFl
         NrSbsyv3mnC4eTbSMZhSXODD0gUn9JKyUw5Bq20EbbdIsTdFgWgCp05SEsl8nxVvjLor
         1j5w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PKjLi1AC;
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b0790b1si74244a12.0.2026.01.23.10.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jan 2026 10:06:00 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-47ee76e8656so34505715e9.0
        for <kasan-dev@googlegroups.com>; Fri, 23 Jan 2026 10:06:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769191560; cv=none;
        d=google.com; s=arc-20240605;
        b=CfhVHFglUDaKfHox0NkzDwIRZA6CksuYd5JX5b9Oz//h/4oDVKUTJbb9XOjPrtxRvG
         yTgx8bYebRQDlzPRonMJ34Iki1gvwUJWpDZONJtTccprtePDrJF/G6/1FctLTr9692Bj
         2NL1iCuuLCs5gGwxm1GwKUeLEBmCCZH+YS9M9TjSqwwd1Ij9IXgBeOPmEKpNF6t8h+gP
         cupvjCfQuDRFBl/s0I/5mLeH8jzlsCrAcWg/wkophFKMRnkHb5vSCDf7uB9fC7CbaR/I
         +KvMt+cLkRO0nMIFhOTAmlG7X7MFDmXNki/VKAi2pXV9p6mk0KOutfsDgD+SAuHoXNSs
         joyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FcLGkCfuB/sIPTdRBcsJjPn4bR/XfGlb046z63lGRwk=;
        fh=YMKnLtAwBreUQ9rGYGNb7iKiL49tXFKwKVtbw+jb3mo=;
        b=VZxOOay/HQjk+EpNB5hA2VZN/IChGyB5sfdDuCheEcT30UcdSp8oUjwlxmmP+r8ESz
         +pNitDkZyUA6zZFP/T4mgJ+lVlntkmSF4Bjnf/Kj9+MODrxmI54rIesHgDn/rut0wRMw
         4NfoXjkerSBCcBCMsN34norPmJvKWRkGWkhJrnhHDVrhvh7FGiuj20jJnfJf8GkgCfj3
         BvNMuzmC4b1UU2e4EGrfszBftE8AiTLsUrQRx+0FneeImpryUVpqupDqbot0Q1os3L8/
         xCs2eQOdJ/WbwLfCtQ0FAyq98H417xu4NK26f73phZvSM01HOz0MvJcGILOH1AIfn9Bc
         LTaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVM73XT9jcYwlQOQFUAzgImAhvzCP6LgfY0T8kHdybZOXmPC2GeGCFnXywwnE6R8MfoBMEIF+8nUdg=@googlegroups.com
X-Gm-Gg: AZuq6aK1h7a/eoubfEhaPHMDSzvV+nxv54vc1TDGlD9JOfvdD/eee5gzpOdvHxu3Ga5
	L9aUBa/zNy//mZT8InTsDZLiQSjZU/FXclT2gsBRydQsDu8LXPoakCwh4ak1rXNbLwrk8uhTScW
	PdepMLPcLVfqqgKifKvnWgo9hsSfBbJp6X5lrOvZwg5ET4ucXF9OZEuMwlV5PXs+6YAIdQ6J9qS
	uyZrenMhl47+r9LlJvvF+Hho1Wl6pry7+Fmwdc2iEaNW8lZQ8DyWXGOo49C3QpISXfymYi0gMNY
	RId6YHyVmkUfMb/4J5TnlIzl/utGYCqDcVmYN6k6KTPRuprc9JSwWV0o0Kd2FYvPf7sXKX6K
X-Received: by 2002:a05:600c:621a:b0:47e:e076:c7a2 with SMTP id
 5b1f17b1804b1-4804c95e12dmr71414205e9.15.1769191560210; Fri, 23 Jan 2026
 10:06:00 -0800 (PST)
MIME-Version: 1.0
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz> <20260123-sheaves-for-all-v4-8-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-8-041323d506f7@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 23 Jan 2026 10:05:48 -0800
X-Gm-Features: AZwV_QjSjoenDUCyXmvsb5KH8Pd0BwP5NV53NJnMQ1RHDoaNt4mnnL7gEc0SK7E
Message-ID: <CAADnVQKW2Z62+xC5NUsx4ynqbwPh5yn_EJJrQ4kcPab6KWUK-A@mail.gmail.com>
Subject: Re: [PATCH v4 08/22] slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	"open list:Real-time Linux (PREEMPT_RT):Keyword:PREEMPT_RT" <linux-rt-devel@lists.linux.dev>, bpf <bpf@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PKjLi1AC;       arc=pass
 (i=1);       spf=pass (google.com: domain of alexei.starovoitov@gmail.com
 designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_ALL(0.00)[];
	TAGGED_FROM(0.00)[bncBCUY5FXDWACRBCXRZ3FQMGQED73RDFQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[alexeistarovoitov@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,mail.gmail.com:mid,suse.cz:email]
X-Rspamd-Queue-Id: 33B3B79589
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 10:53=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> kmalloc_nolock() and kfree_nolock() will continue working properly and
> not spin when not allowed to.
>
> Percpu sheaves themselves use local_trylock() so they are already
> compatible. We just need to be careful with the barn->lock spin_lock.
> Pass a new allow_spin parameter where necessary to use
> spin_trylock_irqsave().
>
> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> for now it will always fail until we enable sheaves for kmalloc caches
> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Alexei Starovoitov <ast@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKW2Z62%2BxC5NUsx4ynqbwPh5yn_EJJrQ4kcPab6KWUK-A%40mail.gmail.com.
