Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5HEXGXAMGQENGGYQGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0861856E79
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 21:22:13 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-411e1466370sf21085e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 12:22:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708028533; cv=pass;
        d=google.com; s=arc-20160816;
        b=eFltmwcEuts9Zr0SydaypVNfNl6ZGPnUF+qwvShMERhNtFXAj+DTDWAVMdEcV5vbGs
         6CLRYeBqmIw0UNoAYChVauJ+KXHR5KFCJpOmAKsDolK8lC98qYwa1UQ/nNjX90yprLcB
         2sZB0f2CCGuY5IYvQoI8rIiPmVCzS3RFXRwLVJQ6jeBDCmvVSUJQSz6N4PGUcUks+OCh
         g0eXkQlb+4nYE6ozC15NvLUOxHe76VsxX17HMim2eUzwY47XUY6BypynfBQXA4oqYMAu
         Z0HShXMLndBtdvk5fud/QEMkBgirvIHlPpgWoBnrn94QfxZLtODuNfQ/ajlRmXZoMGHV
         AO+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=UtEGtxR0OVkhqk90+daaTrSbakZR0dXxWC6IQ4rMFFg=;
        fh=AmjkXKv9dxGMhaqTYg0+xVaWI+Key1Lzbx0rjwvtBMY=;
        b=RWadv8kjstW8qCGxZTeG60uV4iB2cy1S7zOR8ZNkhSA4tZxc2tf5/pqc+dp12KTdcp
         xHkOFnOTT1o4q0uhdBGxqr+m/FsBZyHXV6yuNnMo1JQlc5a+hafX9cfY48epVOKuyygx
         hJbD963D9M04VqJ8as0i8gX8GXuXkBYA4hcvs+6hvJK7Lz69v6WgEJ6qWQIgvvNsdrsJ
         cPNMANspQaz81mmCLTWOAH5BRJNg7yCdnHVg0QvV/z0j3Vi+xtgbzV4QeubuZgwp67a3
         ycdCG8YYSWR8BBIDRCFtoUxNZCq/Y3UHz74FcM5+RMtZM8/B85NaSITyirtly+tXnDC+
         iF7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="fyDN9U4/";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="fyDN9U4/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708028533; x=1708633333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UtEGtxR0OVkhqk90+daaTrSbakZR0dXxWC6IQ4rMFFg=;
        b=NmZZ62hn7E5AnhXghtphTJ4efixW2Eb+q/ak0tpdbtPLjh4gAxBgQ5x5mOn+iHSURE
         AW4XmRSKIZx7ORoSeFai7L6cCesQQtXtjuk/of3OxCP/D9R4Vmu16MAFf7vd6GWjJhkO
         FkZZUu8Bf5ddKnzs6PcKuOwF5S26xGV2XuwkXXJQsiHb6KtLSU1b8CC3pustO40AGDH3
         lWdaquM+/JVOh/6XiLYuiwV+HIeHfbM5T+EKLWPyj/RCnu4WmxP+yNp2f/98dQ7R0aua
         Ea3OeWd8EXCgG9SDQtmWXHt9Et6AtXJEV6HjjtFDmfgpiJ5OZEsidOLAumc5ispzoUiv
         Lifg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708028533; x=1708633333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UtEGtxR0OVkhqk90+daaTrSbakZR0dXxWC6IQ4rMFFg=;
        b=htE8g/d6TA/6dEXLDUFDFr9lRxRemU2OQVHNvpb1Uqb+qyarbD+9WMTEhC46b5RbKT
         DDwnO6+Z4WAMHmirjdF8cxM+wGNKAPIL3sTOdgCynFC4bUK2Y4sErL76jQ5bw/ZuF6+C
         2eQlzHAJsifkWy8r0MndsfCwFff7n7qdWzcdc2j+ubFm0//Aj8ZqCFGWdiAiqZ/WSsMA
         n+DPBs1kPyZg1lHg/I4yd4bCbuVc8/V3X3kMvlg/ehB0XTCJ44jp//8bfCuz+3e8aUQH
         BuEQCdvx8EmeFmf3f9QlL4aDzpbZhZSt0/UHy/te2q0GCXhDQyWaLs4+eLHraqNBS9r7
         Pdsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6j/cdhi8wneYklURr2ZMVRyEtStCc3XvEqMXbnSdUcNJoZ5NbIzm4kfYQkK0DV3jvTKVMylCPZjHR7w8zsNyGvo2Y/fsm0A==
X-Gm-Message-State: AOJu0Yyt0LOz2CqY9cY3bEfVwWPG+jCx/yUPa5OJnGN6PcTs+veSm4uU
	3UKRkeu9AMUJbhX/w5nyjMkjP8Hk+e3MdWeC5gFD9iFqrTzYX9QW
X-Google-Smtp-Source: AGHT+IFAQeehuk+4WXmNm0eetndZN3KLfPQpUwDKYwvTipVUcZi60qhbIrjZeoKe4QZobp9bAGv1Yw==
X-Received: by 2002:a05:600c:510a:b0:412:283e:5782 with SMTP id o10-20020a05600c510a00b00412283e5782mr1362662wms.28.1708028532260;
        Thu, 15 Feb 2024 12:22:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d86:b0:411:f09e:9d69 with SMTP id
 bi6-20020a05600c3d8600b00411f09e9d69ls52494wmb.2.-pod-prod-04-eu; Thu, 15 Feb
 2024 12:22:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwfqArUEULj+TdXw0M6XmErmIhcxFsc9OtEus675/YEUqNFFZUXfYzcj6y1hJixZ+/k1s51xDYVwr4+C4dy/9UHUWeXdWBf12HTA==
X-Received: by 2002:a05:600c:6008:b0:410:c127:62fe with SMTP id az8-20020a05600c600800b00410c12762femr2260870wmb.1.1708028529703;
        Thu, 15 Feb 2024 12:22:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708028529; cv=none;
        d=google.com; s=arc-20160816;
        b=CCp2UtEKEnMHDI8xhwjwlKXnCovAhIPZPgIjH6NmxkSHsFbcOivHMQKRGEZnO54ZYA
         2m9tULX6ScOQ9hTmeYs6MR856uQOfCNECMh1Kp3p7GxODldvDwLp3Ng4iXJE5phnM7DJ
         nzmWB2hZevvid0+tm3/1m4ZQWRSkWrOGGgOfylKLVO+NyuU24oegONl05mbo7yR7ihZC
         wWYbeuFCkPlj6RsEGcu6Wzp8bn4ISAIZOXnfjtwL1iNaqKmD7Oo2uUukM++A897T2e9m
         YVWoKdliDFos8iudXGyGaNuTcm3SzGes4RJzSM1Bw5+nckZEFD3o6a2pW4MbOmm1lPJz
         R9iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=+PvwLOkhLs20C3GH06d6BicWz8S2K2wPQ3EkGdP8tjQ=;
        fh=12BaHlFAJdSN7Xev2mRW/iyNNXQgAvODmVaAkcA/+nw=;
        b=iG3Z7Z1RIW+ZYSiCOHgXZ4Ihqc2eRLh8T1mRGoL1VK7rX4YMpilwAwdEIzVGRw5ABQ
         cNw7eS2jNYdy6p84bkjpHFRZPegD6ntLdLSbbX6yKe1ZM9YXod4e7irgFf4duHIvXQb7
         dz9bD0S6/7ZKekPEQFbzlDV6d5FK6tpzSMt722V62BSu/VWwQRDNhVvRJpVtICls24tB
         MplUGLocjxzTbsRS9lqhSb2iEWfy3aiIhdMYDGSWdH95Joa1wBjGZy/9/Tdx2NfWUOV/
         2IcF2jN4XeUIA2nkk3JGepfUe0ZR3kHw+dJ+rBIZ/YoEMZ+5RkA67jfkquGFIMkxnWkn
         nPDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="fyDN9U4/";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="fyDN9U4/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id n25-20020a05600c3b9900b00411c092ef0fsi4957wms.1.2024.02.15.12.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 12:22:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 176491F8CC;
	Thu, 15 Feb 2024 20:22:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6778A13A82;
	Thu, 15 Feb 2024 20:22:08 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 9ufzF3ByzmWgOwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Feb 2024 20:22:08 +0000
Message-ID: <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
Date: Thu, 15 Feb 2024 21:22:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Content-Language: en-US
To: Kent Overstreet <kent.overstreet@linux.dev>,
 Suren Baghdasaryan <surenb@google.com>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
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
 <20240212213922.783301-32-surenb@google.com> <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [-1.59 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[suse.com,linux-foundation.org,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -1.59
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="fyDN9U4/";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="fyDN9U4/";
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

On 2/15/24 19:29, Kent Overstreet wrote:
> On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
>> On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com> w=
rote:
>> >
>> > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
>> > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.co=
m> wrote:
>> > > >
>> > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
>> > > > [...]
>> > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodema=
sk_t *nodemask, int max_zone_idx)
>> > > > >  #ifdef CONFIG_MEMORY_FAILURE
>> > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poi=
soned_pages));
>> > > > >  #endif
>> > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
>> > > > > +     {
>> > > > > +             struct seq_buf s;
>> > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
>> > > > > +
>> > > > > +             if (buf) {
>> > > > > +                     printk("Memory allocations:\n");
>> > > > > +                     seq_buf_init(&s, buf, 4096);
>> > > > > +                     alloc_tags_show_mem_report(&s);
>> > > > > +                     printk("%s", buf);
>> > > > > +                     kfree(buf);
>> > > > > +             }
>> > > > > +     }
>> > > > > +#endif
>> > > >
>> > > > I am pretty sure I have already objected to this. Memory allocatio=
ns in
>> > > > the oom path are simply no go unless there is absolutely no other =
way
>> > > > around that. In this case the buffer could be preallocated.
>> > >
>> > > Good point. We will change this to a smaller buffer allocated on the
>> > > stack and will print records one-by-one. Thanks!
>> >
>> > __show_mem could be called with a very deep call chains. A single
>> > pre-allocated buffer should just do ok.
>>=20
>> Ack. Will do.
>=20
> No, we're not going to permanently burn 4k here.
>=20
> It's completely fine if the allocation fails, there's nothing "unsafe"
> about doing a GFP_ATOMIC allocation here.

Well, I think without __GFP_NOWARN it will cause a warning and thus
recursion into __show_mem(), potentially infinite? Which is of course
trivial to fix, but I'd myself rather sacrifice a bit of memory to get this
potentially very useful output, if I enabled the profiling. The necessary
memory overhead of page_ext and slabobj_ext makes the printing buffer
overhead negligible in comparison?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/320cd134-b767-4f29-869b-d219793ba8a1%40suse.cz.
