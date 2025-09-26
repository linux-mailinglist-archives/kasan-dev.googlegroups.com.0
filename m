Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVMM3LDAMGQEKZOQY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D996EBA399C
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 14:25:58 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-61d31626b01sf1977379a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 05:25:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758889558; cv=pass;
        d=google.com; s=arc-20240605;
        b=lPGo8B7K36ZVjXGlKj7jPLECKkpBSEYcez2GuIrxMHUwncuNXmd2RM5IJOqI45d8jj
         CY/9HbBjBukS0/nNcrfwPC5w+paOBtcZywXQM17lyJpCrw575aBm6gLQywDmWxZhlmTz
         zYFwuLwMGtXafpZW9PPMChaG+QwjD2hHU5xsYElAKBbSk7KYI9y7tToeZnNmrBmpoN7d
         zdZ+7M+iMJPhkzfd4FG7agt7JRKQz1sLiTYGRlr6qIhWKDLF9V1+9XSaiNSUY2eQiwW7
         +Rk8hmXaRQjw9jVIeGQv4Op1SrzkFKRutHTTYxIoRmnTGqOFR3lkSMxUSdh2dtLHACBQ
         mkaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=mnnqK9rjzVuPE57m1oXmCwAff2GsbonRcoo28X4T7U0=;
        fh=DAiwHUEKEWXJiuh73wIpJ+SW3MPsDpzcWCX5Gd8PF+o=;
        b=AzwIQ6Hp25NS45OiCz3oteOVuK95jj9OHwJC86f9Q7S6jKE3bXu4R1TnHGOjrmMUM/
         sDcgz9hpqMWvwwZoUh7s61zkGrKFrMvNk12ZAphtCpQK/wSHEvmc1p4By+k2rnZOYmHN
         uyWYhS9oXzRqyAs0jKLMcKbfvWa6BuqZ0Tl+JonK8UbSzTNlffmA6c+Z+iCfjgaPA0Vt
         tq2nHzMmLK5ym2OifniDlgNx9JtBuf7gR2tLmXPEoqZZbBH/dgaF1RZqfP8V8BdDZRxq
         FwIog5BA9rDFTYBbQ1JsmrSFcYoMTuKj2zVqrPJriK3oPTIbv5L6v8FypJxE1veMKYzl
         DO/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qBPVxGlH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qBPVxGlH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758889558; x=1759494358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mnnqK9rjzVuPE57m1oXmCwAff2GsbonRcoo28X4T7U0=;
        b=brkk8GiIzer9MTMJKYDNmlHJQmqugGIu4by2t6Gm0o6p52hZxko918G5HZoEWO5OUX
         ESXoo4sDv52B8X/a/aON/RkZnN/N6Z//TpODGyqA3JM3q6qTsT4/A+R+dTI9thdfeWwY
         MeqPsCXPJp4eseZEVYpTUf3C2QUKG8WIqMB6xobRv2RrouHbjNuTTp3NisQ37Rig28Iw
         DJaWKI7woGymqExp8+2PFVXK7j1Mo7i92AfBcaxC5TKF0dPUIjZcV3U20ZXfsvKB7TCl
         UL4f/S/j37QNI792IISQ3RaYFBEPCtmibWJ4AQrZwYcU6xxgsGQMR1GIhkpxm/63aot8
         rEsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758889558; x=1759494358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mnnqK9rjzVuPE57m1oXmCwAff2GsbonRcoo28X4T7U0=;
        b=dmxnsdFaK9tN2qpjz4n34Dx2ktVxi7VYW2E6ZsLjzG6iqDCVztFvWDh42t8eVrWJ9s
         jb+/RllCH5GuiUnqul2W8lzAopt31lFzHI+AcMkKeuabYzEj+uSyBm2sv5U2awEe63Kz
         FUWBaf+Elny0sHCZuX7LYAkh08cweWiGugESfe1X1LivXsaTmpk9FQJJ9YuqTFHJp1+X
         dxL3AG4nC7dVzdLKC5h55jOEeRqLw44iTlo2ywrd0WSj3P8unucT1f55SYVIVY7eREyW
         aeg0B0l2FdcRWtDCaWMSqV62wCI+FHz7e2DNtou4jxrUdZwJBct/9ZEjZvujLjn35H7s
         MaoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyfqmGycsjH6G4nR0C8fWX7t55yPzUn0AWvZFGMZli4Pi88E8gjGvxUAgk1zdxHCBuiH5A0g==@lfdr.de
X-Gm-Message-State: AOJu0YwhGP6cAim88ZCHiJ+D+7aF8LBqePWbgY+6TNFKdAoTjcq4NHMX
	msvMlCyOiVyBDGXd3zmrQE7tiM1nUmIol791oW3jdXksphFxO6/RbER2
X-Google-Smtp-Source: AGHT+IH5rrHe/uUSia+xHxK0vYXUdqq9M/xcenjDb848PysDTBmooLyCuJgNEzkSf0/AUVxGxGeqSg==
X-Received: by 2002:a05:6402:518c:b0:62e:ea24:8a17 with SMTP id 4fb4d7f45d1cf-6349fa842famr5947076a12.18.1758889557860;
        Fri, 26 Sep 2025 05:25:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7BPUeGjpyKmjwVAxSZnM0kgZz2VGthPUYG3l6UYPOIsQ=="
Received: by 2002:a05:6402:26d2:b0:634:85b5:86e9 with SMTP id
 4fb4d7f45d1cf-6349e9f17b0ls2126449a12.0.-pod-prod-04-eu; Fri, 26 Sep 2025
 05:25:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/nkmnmePzupY49hrJNnTqk1L2as1Lxa8xD8UBiYWg1BD+PrUyL55h35XG2wHorqXKSfTizhmR3lg=@googlegroups.com
X-Received: by 2002:a17:907:7296:b0:ae3:b2b7:7f2f with SMTP id a640c23a62f3a-b34bad2854emr871524466b.40.1758889555010;
        Fri, 26 Sep 2025 05:25:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758889555; cv=none;
        d=google.com; s=arc-20240605;
        b=YNUVgnCUvyorALMOAWjSDIQ+3ewM+v0/SyMiyjsPFsdz8/kSMkb5yUGgzI6Nc3+xzd
         6+NSIaXwxZKnSh+qomMZ8T4TyKUfGedkPtsLd4Gv3Wlwja6pZERrcitwUqp7dB/3IuHQ
         2vDKcpnuZWBLpdYKxeUALwrVf57rhcnRfjAAKJl0zQpohVefnAWnHlxjfbI7QlbsjCxz
         4xzRFTnTImg+KfA1a9p21cEt+x0ldqJx1+rOR8kqUcOJ/c0IRKW8hXx58YXylWo+nc6i
         Ybvuey3Hqd/lSlXSbMG2E4CEpU03KNYxTKOFC+7JUy5mlqKHGH58+V3M03cvJOz/KqFq
         1YDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=UnaqUPfT6F2SYdrHgWkuz0x4Dq1KFNAs2dZR1oVzZDE=;
        fh=3DK3g8ZywPHV+8uQppqFaRVSq6ga4rLN9EHfHo8IPbA=;
        b=hv1olz23SkI/Q3AEVKMmQRq25k4olqlUjhi4WcCE0vxv0+CtQxCyYrtyQ0YdlL7t2K
         UeI0SLOUJfHeznvh2XSKyz4LLUvhCmHzjZ8QAgNJIzWNrKPmeNCJV4B7KmCq6caK/bsi
         wn3wx+Z0zwdw3f7kQk91x11H2yo2OtVKUPGsStDbDZfzFckBnka0TqsT98hI8guj3hRp
         W2OKKbPlHeCWwrALLUYoZMUoPG5ZvjjFix31EfUD7ISnMqXwjW5RJ7t91BtK+gP5i5rK
         sUU1jtt65Ru48HSg/0ujBP1GjC8tFhYGy2OoY3qJ6Peh4BtRdEyElbcUbv5Ok4uai8FD
         chag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qBPVxGlH;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qBPVxGlH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-634a36522f2si67535a12.2.2025.09.26.05.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 26 Sep 2025 05:25:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 82D0624197;
	Fri, 26 Sep 2025 12:25:54 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6D4081373E;
	Fri, 26 Sep 2025 12:25:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 35hXGlKG1mgnRAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 26 Sep 2025 12:25:54 +0000
Message-ID: <7a3406c6-93da-42ee-a215-96ac0213fd4a@suse.cz>
Date: Fri, 26 Sep 2025 14:25:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [slab] db93cdd664:
 BUG:kernel_NULL_pointer_dereference,address
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>,
 Suren Baghdasaryan <surenb@google.com>
Cc: kernel test robot <oliver.sang@intel.com>,
 Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>,
 oe-lkp@lists.linux.dev, kbuild test robot <lkp@intel.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 "open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>,
 linux-mm <linux-mm@kvack.org>
References: <202509171214.912d5ac-lkp@intel.com>
 <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz>
 <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz>
 <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
 <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com>
 <CAJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF=ZzNOfQ@mail.gmail.com>
 <CAADnVQKt5YVKiVHmoB7fZsuMuD=1+bMYvCNcO0+P3+5rq9JXVw@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQKt5YVKiVHmoB7fZsuMuD=1+bMYvCNcO0+P3+5rq9JXVw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[gmail.com,google.com];
	TAGGED_RCPT(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCPT_COUNT_SEVEN(0.00)[10];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qBPVxGlH;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=qBPVxGlH;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/19/25 20:31, Alexei Starovoitov wrote:
> On Fri, Sep 19, 2025 at 8:01=E2=80=AFAM Suren Baghdasaryan <surenb@google=
.com> wrote:
>>
>> >
>> > I would not. I think adding 'boot or not' logic to these two
>> > will muddy the waters and will make the whole slab/page_alloc/memcg
>> > logic and dependencies between them much harder to follow.
>> > I'd either add a comment to alloc_slab_obj_exts() explaining
>> > what may happen or add 'boot or not' check only there.
>> > imo this is a niche, rare and special.
>>
>> Ok, comment it is then.
>> Will you be sending a new version or Vlastimil will be including that
>> in his fixup?
>=20
> Whichever way. I can, but so far Vlastimil phrasing of comments
> were much better than mine :) So I think he can fold what he prefers.

I'm adding this. Hopefully we'll be able to make sheaves the only percpu
caching layer in SLUB in the (near) future, and then requirement for
cmpxchg16b for allocations will be gone.

diff --git a/mm/slub.c b/mm/slub.c
index 9f1054f0b9ca..f9f7f3942074 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2089,6 +2089,13 @@ int alloc_slab_obj_exts(struct slab *slab, struct km=
em_cache *s,
        gfp &=3D ~OBJCGS_CLEAR_MASK;
        /* Prevent recursive extension vector allocation */
        gfp |=3D __GFP_NO_OBJ_EXT;
+
+       /*
+        * Note that allow_spin may be false during early boot and its
+        * restricted GFP_BOOT_MASK. Due to kmalloc_nolock() only supportin=
g
+        * architectures with cmpxchg16b, early obj_exts will be missing fo=
r
+        * very early allocations on those.
+        */
        if (unlikely(!allow_spin)) {
                size_t sz =3D objects * sizeof(struct slabobj_ext);
=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
a3406c6-93da-42ee-a215-96ac0213fd4a%40suse.cz.
