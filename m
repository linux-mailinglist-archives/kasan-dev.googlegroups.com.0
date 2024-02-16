Return-Path: <kasan-dev+bncBDXYDPH3S4OBBIW4X2XAMGQEVXNNLXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 62A9F8585AA
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 19:49:07 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-51176e89e21sf2129280e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:49:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708109346; cv=pass;
        d=google.com; s=arc-20160816;
        b=CjXA9m2j00HGBaeXRI+AGs2DX0X7nyeH5KxyaInc28PWFTu3FhuMUnD0HiBIQwju0p
         TD7y4P072OzR/IcPlJtpDQeF2PntWT/FkGVA7Js1h4TLmggz3DJAEyAU3tMqzPpm75lD
         y3sfoI8vclnoZ1+FgvkAEM2dAURarcbELajU08tNqaJD5cxdqCCOb9zqqMJ9YLOFRWP4
         NbzlXk/lOxNPW5PT4ewqFQZyJPjLURO0Cvxlt2+UtGOzND8eJuQB9zjBPuihHBy/VnmD
         M0tV8vaPcDTNJwkO1/oufzoPk6QUsv9Iba3JJM9l5m8bS3RQnn9D+3ODiMOmu7SGAey3
         WmMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=aVSt/D2/rjjih0udGAmit/Np482pK7xPDfgVGF3y8Xo=;
        fh=frYUyrfEd0DRL8T8afI6IuTz+Ek/XHhfaoyWsg0YCFA=;
        b=mM5idKLOp3tes+YAEf2lZ0JO06gVdHxAe7t8ilSbsgyth6fqG0J3Qpe5Vo927MZEOV
         fUcQqk5EHyZL5x1BmDDXIoesg/uaFzA59ZR5ghdP5hgCcaJhkCPfVZvFM3SQuqm6tOzF
         /uUvGOqtUgyqanSPqSNuc0Np2mSRKFo4kn85BsTaWzzedsiQoIT/SaZ5sxsubVjfDNj/
         jc8Ftkaq2RwKNVtgxM+aCW63HMIck0mFOIdw52Cwi+9rf+J7aqH39XxxLBKslEuRxttf
         bzfIl5qJu3UVxASspyeOcyBmRLKumq8ZESCCLZSDUKXYd+82nhSHFP7Htewf3QUH1/gI
         CKVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IczKkH7t;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rwd+seiT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708109346; x=1708714146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aVSt/D2/rjjih0udGAmit/Np482pK7xPDfgVGF3y8Xo=;
        b=H5kpzBD3cII8DB+ePKGn1LemJD3GPxy4XE2zOP4iZvC3yc2x/i/KBuTkYMd3dAEWnu
         1D4pnkOcs97pEzOZlD8S+Ne+Nt7wViywcY9wpalZrgnMpT+MUfyMqBNdP2j1sTHnCaTa
         9WLBH7mD27vf84XNIOT65rtC9yNfSJnXfGOBeCQRQDAR8/JN1EHrAYFBkOUlwb7b6Exf
         7ZMjKXJelpIfYUa2uyqPgeXF2tAVVaJ1RxEIP8YXn97bexw9MXPiFdncdIbYj4LCl0je
         TX661jOsRcjfaejfsj2ahAtbPSuogr7hnj9fahJfvNbuqC49Q930NYBN1ZvjxEkyuSRL
         uV+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708109346; x=1708714146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aVSt/D2/rjjih0udGAmit/Np482pK7xPDfgVGF3y8Xo=;
        b=MSuBM2cqf+g0ymgfxG0LqPSFKF1C5GTB8YEjUu3XYJBk29jkDHZdOQhgYu6NJhGutr
         UXKjxb0DBji8h/BXYGiMA6N1LICL+i5ZGVIS7CeWIlv+ve/sfF+85TVtBy7DL57mh9su
         daODUe2Zi17I89uON734DcQ60/e7FttGmjiJxyuW8vRalsMU8TrA5RAs7assX7ox6J0y
         UwV0+xupgK6JP4EoBym8s1bXEdIwDw4X2o39vhVTH1zfchuToEhxvH8M5XwTvfZCnTjw
         jKJt3sS4SiwuyCE0+ZBOJFJjQeCgQRFGqJWtc7dcGsaMkx5A+9UojMcus1DaX2oWOkk+
         FM+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNegQSt1uG6NPPAN4547lyfzkkoFohdUmlPqRdq3UBVxOzjNXg/n7f0Uu1MU6zwrNY8kRqTHPiwwKDH4lfRmoAAQNx/AMRUg==
X-Gm-Message-State: AOJu0YytXJtyljqv+Z+9sQMfWxWlpft/EUNlUwfJM+jl8UERgbln9NPK
	W0JhXRlI1RsEcvuNcH6ooDvnryHqjdKfwR++uAAUvZAAL/A+RE7s
X-Google-Smtp-Source: AGHT+IHsRDoUOtDjUHOgy22NRVBIAFtROt0ievJ46cjfIBSVyFqt5rSCpnD57iKSnYxboTCweo4Jvw==
X-Received: by 2002:a05:6512:11c5:b0:511:aad3:8cc7 with SMTP id h5-20020a05651211c500b00511aad38cc7mr4209858lfr.11.1708109346370;
        Fri, 16 Feb 2024 10:49:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:228b:b0:563:fcad:fc32 with SMTP id
 cw11-20020a056402228b00b00563fcadfc32ls381666edb.0.-pod-prod-09-eu; Fri, 16
 Feb 2024 10:49:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWoElYWZM27w05YEGFUS1IB7TsuIE17Pb/08KrqIxbClta1SzDcvisG8wViyTZYz7fQehJN64Md1OX0w3CN9LDWhU6/zyOR4cikZQ==
X-Received: by 2002:a17:906:5f89:b0:a3d:5e44:83aa with SMTP id a9-20020a1709065f8900b00a3d5e4483aamr4113588eju.20.1708109344488;
        Fri, 16 Feb 2024 10:49:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708109344; cv=none;
        d=google.com; s=arc-20160816;
        b=GDIkoz/a9iEP2AV5027ZxF7SYNly/X9YKf+Td7JUZlI5ZxBZuZco6tYUFwrqf6RtPw
         tsl0FgGKmT1xmZrdz0hgroihJp0iKVI71L2jkuRU7mTbCwJw+neDOdFRj03RvzFjzt7A
         dnpJLdB0l3YlPc190DYJR36QQYwScw30VYm3QqBWTvEiiNuhepK4xzMzSm1k5mwDl732
         l5VDHTc1LaN2wEuA8A2W8j14Eeam+gegh5CN6Yr99PPanveite6jldOzdTTUexD8Wttj
         0BGjwpecHjN49hTvbbHu6xnm/1aI4o6CkiYCZwSlfO4L9g+kd4OY8pKX92Gmu4rV7W7S
         Ze3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=LIy+v1QxzmWGHbmMqIx5w7+6IieTl4Y2Xxq5xuO/0u4=;
        fh=6zYKUpAcwdtAhEm5ZX+apM+Nxyg7QbDlMYIzvPq4OGY=;
        b=sbLmWcbuSG1QUy8AKotK5ScVDNRVtK7lulu3WV4QNqDmJdxCnzmx0vwttrn/242o+2
         Nq1qlIi1rqJSG/3NovEEBZ2JhjZnPGLpZEDpkQKT/mw/hWIIIbUvI8TWTVo6lIDtSonZ
         uw4kDORysKfeRVKhLjkTlmEqRugYYPat5/0qIlO7S1iZYq8f1vkejXAJDfmEwi1aEvpp
         gQg2KG/ZO9sZanq1/udfmhF8558Ie5K5WlXH+Y0MqfyxzytByFgHrbUBqTLerpQh33Ep
         E9DBHnxKyqBGQ72DXG76IFXO1XiA7bsHNnLF5Q2AkqiOtMXXL1z7YS41BF1jBDDrj20W
         W+Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IczKkH7t;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rwd+seiT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id xo9-20020a170907bb8900b00a3df74cc489si24832ejc.0.2024.02.16.10.49.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 10:49:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id F1FF92212D;
	Fri, 16 Feb 2024 18:49:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5AF8F1398D;
	Fri, 16 Feb 2024 18:49:01 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id upbPFR2uz2WgbQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 18:49:01 +0000
Message-ID: <198f835b-35d6-4ae2-b993-675c871c621e@suse.cz>
Date: Fri, 16 Feb 2024 19:49:01 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, akpm@linux-foundation.org,
 mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-8-surenb@google.com>
 <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz>
 <tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut@5dlfmdniaksr>
 <ab4b1789-910a-4cd6-802c-5012bf9d8984@suse.cz>
 <CAJuCfpH=tr1faWnn0CZ=V_Gg-0ysEsGPOje5U-DDy5x2V83pxA@mail.gmail.com>
 <CAJuCfpGBCNsvK35Bq8666cJeZ3Hwfwj6mDJ6M5Wjg7oZi8xd0g@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpGBCNsvK35Bq8666cJeZ3Hwfwj6mDJ6M5Wjg7oZi8xd0g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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
	 RCPT_COUNT_GT_50(0.00)[73];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=IczKkH7t;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rwd+seiT;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/16/24 19:41, Suren Baghdasaryan wrote:
> On Thu, Feb 15, 2024 at 10:10=E2=80=AFPM Suren Baghdasaryan <surenb@googl=
e.com> wrote:
>>
>> On Thu, Feb 15, 2024 at 1:50=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
>> >
>> > On 2/15/24 22:37, Kent Overstreet wrote:
>> > > On Thu, Feb 15, 2024 at 10:31:06PM +0100, Vlastimil Babka wrote:
>> > >> On 2/12/24 22:38, Suren Baghdasaryan wrote:
>> > >> > Slab extension objects can't be allocated before slab infrastruct=
ure is
>> > >> > initialized. Some caches, like kmem_cache and kmem_cache_node, ar=
e created
>> > >> > before slab infrastructure is initialized. Objects from these cac=
hes can't
>> > >> > have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to ma=
rk these
>> > >> > caches and avoid creating extensions for objects allocated from t=
hese
>> > >> > slabs.
>> > >> >
>> > >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>> > >> > ---
>> > >> >  include/linux/slab.h | 7 +++++++
>> > >> >  mm/slub.c            | 5 +++--
>> > >> >  2 files changed, 10 insertions(+), 2 deletions(-)
>> > >> >
>> > >> > diff --git a/include/linux/slab.h b/include/linux/slab.h
>> > >> > index b5f5ee8308d0..3ac2fc830f0f 100644
>> > >> > --- a/include/linux/slab.h
>> > >> > +++ b/include/linux/slab.h
>> > >> > @@ -164,6 +164,13 @@
>> > >> >  #endif
>> > >> >  #define SLAB_TEMPORARY            SLAB_RECLAIM_ACCOUNT    /* Obj=
ects are short-lived */
>> > >> >
>> > >> > +#ifdef CONFIG_SLAB_OBJ_EXT
>> > >> > +/* Slab created using create_boot_cache */
>> > >> > +#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x2000000=
0U)
>> > >>
>> > >> There's
>> > >>    #define SLAB_SKIP_KFENCE        ((slab_flags_t __force)0x2000000=
0U)
>> > >> already, so need some other one?
>>
>> Indeed. I somehow missed it. Thanks for noticing, will fix this in the
>> next version.
>=20
> Apparently the only unused slab flag is 0x00000200U, all others seem
> to be taken. I'll use it if there are no objections.

OK. Will look into the cleanup and consolidation - we already know
SLAB_MEM_SPREAD became dead with SLAB removed. If it comes to worst, we can
switch to 64 bits again.

>>
>> > >
>> > > What's up with the order of flags in that file? They don't seem to
>> > > follow any particular ordering.
>> >
>> > Seems mostly in increasing order, except commit 4fd0b46e89879 broke it=
 for
>> > SLAB_RECLAIM_ACCOUNT?
>> >
>> > > Seems like some cleanup is in order, but any history/context we shou=
ld
>> > > know first?
>> >
>> > Yeah noted, but no need to sidetrack you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/198f835b-35d6-4ae2-b993-675c871c621e%40suse.cz.
