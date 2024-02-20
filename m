Return-Path: <kasan-dev+bncBDXYDPH3S4OBBEW62OXAMGQERDBSHUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6366F85C398
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 19:27:31 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2d0549b7241sf32961401fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 10:27:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708453651; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z8hAsaWPw9dWAbOC/4xgI4QY7RFyrpKcvfRQV9vpscaZtRl1cUEPwYnw3cYrd4mhh/
         Bgf5FedfzWfnJZoe93wKf74CFzi+wC6j2+huaL3KAY1JHGfzB8F3fQotrQ/4vpJdEkOD
         cLPFSJwK/8MMIO47JFAQWLb0Z9ZwmBGp9YH15rYlajgDuEmiyTvdfI6f9qkIRMPH6ype
         KEotzaakLZeX3q6oBfPx4IgbAmk2M7I6hU6fmRi5XvpZYrY+1YVvWOszox42E7YsanKT
         rxmzubnM0a2XX+mq+yKxccdgD2KBAZ3/SW8ZDLkJhQOTJ2SfzItafq930N3kwnyvrOm/
         5LMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=peZ7LB7ujnzJV6H5H7sOALdt9idAJbo4baoLWs9fwgs=;
        fh=J/f0VUCZ4t6h1C83n9dCV5qxeKF97bVavDYSMuYyD6I=;
        b=zTrRDiEt+cZEi4D6KCjPL5ZTh9kI7PGryxUuQNy9eMquDmq7G6n5TSAnGTYWeTDlP0
         D5ewa0888gQ/iNY0LcD3LdIQzU0VwycEm3E0BZ2RAvruqTv3TcfC/7rg/oFHON2AUz0g
         nbqWt0VUsJkro5L32D9KxKh+fPPbwRrJlpMV1J11d9Fz0XhFMoYWqqi1bDKYadQAtcAs
         NJj2OlpyNLiF+Z4pt0cmbcsHDl8T0vlvrPZZQsSmOx4AQpflbkdTZ5EujzOJLF28Qtbq
         lvZwBKm4YuYz/xGZ3UmlWksJqPxoz1ApWCgSf+8YD2qpjtXOD2g9wj5xImS9g1MejoFU
         zqGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IxxD5z05;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IxxD5z05;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EGjwc1aS;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708453651; x=1709058451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=peZ7LB7ujnzJV6H5H7sOALdt9idAJbo4baoLWs9fwgs=;
        b=KkHVJ5sT3b7NQUq/OL1TbmsdZMtagh5G7NWuWYdt5nd2JbrN1bsoe93urP28jgs6Q/
         Vt4RQbXw8jnRtouQgJ2UBkFEPAlccJ/mukFadN9YAocl97y4dI6D2bOQIusYDxb2yGY9
         JC5gJWsosRhhHPsiMybaNhgYbBY64+FcJlSzunNFgkyRxvAXy1T2du0GMi1U5AEe5orH
         7b44kEGwRWfCRPpiTfTKl+Zugz/TV6aSWm6ex5kEcsYA6KCVlwvLlrfir97in4v1vNE2
         c9JxoP5yMn4ApwgW4ao8Uga7hSCs6iXZ1r461L+VezmBNNJvamXkVMCLonTPBx1SXuVP
         AK7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708453651; x=1709058451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=peZ7LB7ujnzJV6H5H7sOALdt9idAJbo4baoLWs9fwgs=;
        b=VbpyAymTi3vGhCzhdpeinge0n3+cEJpyDjvjhgHf9F4nHRRDSXdT1MNIgBbEDwK4bx
         me/uJKqn8659OEyiohDmlR/VgZ24DDtsTaLGVbKD7GXl11RC4Ne2lWPFp8mpQGdikLy2
         7jOVb3Gr33pB5UwrY61Ar8sXF7vUKKLNJhalk5cALq4yFYl3m8Fatfwzxe0QfQypqX5R
         k2FrHQrN0TTdslAJuJOLdA2BpWEw8Hjn6qpTO0du+K3Q9z73HhOvONAZgfZE+7uJchNb
         vyLMv5xMaNAcW2Cod6WslpP+LhTWrBCXRsTp+5Tl+GOZUMHTHJ+WnWcefC+1S2HXtq31
         obOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZl3vr9+FXtlPVWKRAr0Nqu04CH0zRNWjUxFmp/r+v4shyLwZW2CbKqP3UGnqotbNTVeKspRj5CJwpz9Dod8TxJ6z1XoewwA==
X-Gm-Message-State: AOJu0YyeaL0jgu41jPPpEeJFB/tgvgacyuY0y79Fds2e7IM/EOx9feLk
	2oEJxVPmKz0BNM9qaYc1KAVHHZOZjwThODspVvsL8GsRJ2/x59iB
X-Google-Smtp-Source: AGHT+IFff6cl+lgI1MkyAEA8QHRTH06pTt4HcNB4I0nmDLqQET12Pnr7gDisiwNrrRWxocnOd+TV2w==
X-Received: by 2002:a2e:4e01:0:b0:2ce:f93b:3af5 with SMTP id c1-20020a2e4e01000000b002cef93b3af5mr6415221ljb.9.1708453650322;
        Tue, 20 Feb 2024 10:27:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a265:0:b0:2d2:344d:f143 with SMTP id k5-20020a2ea265000000b002d2344df143ls700276ljm.0.-pod-prod-00-eu;
 Tue, 20 Feb 2024 10:27:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxVYoMEWts0oNybnGFLEhGD4MqM9Ny9ZqQJom7z7uEnIjGDmBU3YPbePPTaD5On+vQUGOyENGcTwR65RibUr4I8cMe6e6NkDnibQ==
X-Received: by 2002:a05:6512:3e14:b0:512:b932:7908 with SMTP id i20-20020a0565123e1400b00512b9327908mr1902611lfv.15.1708453648159;
        Tue, 20 Feb 2024 10:27:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708453648; cv=none;
        d=google.com; s=arc-20160816;
        b=cXTdQSuhHT7M2/4EHtBLdNNLbKhuLWGIM8nWie5RS8pakFy6EBZNEVN7k+xvUJqkX8
         DfXSRGEJQmKJM+iEolRKGeoJ4+b1Sl9oBCAmlnMl9VBcR5ms9QTO3sM3CtKkve1JRRS/
         YDgQb2zuusTliudfo1qsv5xurAYK5V8GDR3K8lSXN9mTwx3POLFuBI6c5Ypv3ng1XW3h
         Znq7d1XlNzcX1c65OaG+PKOzkIZmzXjZe8AgvVyLXO44okEtFjhJf+AOwx4Bl5cGKbz+
         yqGA0ihfElBTKrZqslzLIYHntiwrbqr///0DT4HmDtcFpTE9bEVtzPrWqSCW661DB/07
         qa/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=ZilpvBzNJyAotgmhs4yPhtveHoML0rb6UBsNzTh2fy0=;
        fh=ZXe+y0jrzMUKPhQ3XkR4SJkSWvjmyvXW+HCAOkuhB2M=;
        b=YfAIim9LlJBRhgN2dw92yEFSwWlhsGKNjox0/C0IEj3oUgQdXtBasl3lAUnOg1tjCT
         Rg/xFG3aFQTdNXPlAq45BxXh5jppzRSjF5Kzfkp/rFJ5PAo6929e+HuGhkXJFHThl+yT
         zEVo6dxXl70YuEpVEbcO4PLHLOPcA5oEdxMGGHxhi7llcSPZvNUxWOW6gdme23t6rL8S
         kqQQpz/c/F6eS8FozSGRwAI2QdksWI1mjx/sLtycOTDpntDEd5YIj7VF8MOZ7BZfMSLV
         MUDlwz/rCgjhP3UViR+fIAPnxdMz8Yow2srrEBgfyDT2gNpErsVglXYAq6Uiopk5Uk/Q
         V/UQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IxxD5z05;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IxxD5z05;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EGjwc1aS;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id t20-20020a056512069400b00511429b36e7si356736lfe.1.2024.02.20.10.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 10:27:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2446421FC0;
	Tue, 20 Feb 2024 18:27:27 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 895C6139D0;
	Tue, 20 Feb 2024 18:27:26 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id zQTVIA7v1GUGcgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Feb 2024 18:27:26 +0000
Message-ID: <e017b7bc-d747-46e6-a89d-4ce558ed79b0@suse.cz>
Date: Tue, 20 Feb 2024 19:27:26 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev,
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
 dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
References: <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
 <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
 <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpEARb8t8pc8WVZYB=yPk6G_kYGmJTMOdgiMHaYYKW3fUA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spam-Score: -2.78
X-Spamd-Result: default: False [-2.78 / 50.00];
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
	 NEURAL_HAM_SHORT(-0.19)[-0.970];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[goodmis.org,suse.com,linux-foundation.org,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com,I-love.SAKURA.ne.jp];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=IxxD5z05;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=IxxD5z05;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EGjwc1aS;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/19/24 18:17, Suren Baghdasaryan wrote:
> On Thu, Feb 15, 2024 at 3:56=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
>>
>> On Thu, Feb 15, 2024 at 06:27:29PM -0500, Steven Rostedt wrote:
>> > All this, and we are still worried about 4k for useful debugging :-/
>=20
> I was planning to refactor this function to print one record at a time
> with a smaller buffer but after discussing with Kent, he has plans to
> reuse this function and having the report in one buffer is needed for
> that.

We are printing to console, AFAICS all the code involved uses plain printk(=
)
I think it would be way easier to have a function using printk() for this
use case than the seq_buf which is more suitable for /proc and friends. The=
n
all concerns about buffers would be gone. It wouldn't be that much of a cod=
e
duplication?

>> Every additional 4k still needs justification. And whether we burn a
>> reserve on this will have no observable effect on user output in
>> remotely normal situations; if this allocation ever fails, we've already
>> been in an OOM situation for awhile and we've already printed out this
>> report many times, with less memory pressure where the allocation would
>> have succeeded.
>=20
> I'm not sure this claim will always be true, specifically in the case
> of low-end devices with relatively low amounts of reserves and in the

That's right, GFP_ATOMIC failures can easily happen without prior OOMs.
Consider a system where userspace allocations fill the memory as they
usually do, up to high watermark. Then a burst of packets is received and
handled by GFP_ATOMIC allocations that deplete the reserves and can't cause
OOMs (OOM is when we fail to reclaim anything, but we are allocating from a
context that can't reclaim), so the very first report would be an GFP_ATOMI=
C
failure and now it can't allocate that buffer for printing.

I'm sure more such scenarios exist, Cc: Tetsuo who I recall was an expert o=
n
this topic.

> presence of a possible quick memory usage spike. We should also
> consider a case when panic_on_oom is set. All we get is one OOM
> report, so we get only one chance to capture this report. In any case,
> I don't yet have data to prove or disprove this claim but it will be
> interesting to test it with data from the field once the feature is
> deployed.
>=20
> For now I think with Vlastimil's __GFP_NOWARN suggestion the code
> becomes safe and the only risk is to lose this report. If we get cases
> with reports missing this data, we can easily change to reserved
> memory.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e017b7bc-d747-46e6-a89d-4ce558ed79b0%40suse.cz.
