Return-Path: <kasan-dev+bncBCKMR55PYIGBBEH7XCXAMGQEYL5EIXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 70C4C8569D3
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:45:05 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-40e4303faf0sf922805e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 08:45:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708015505; cv=pass;
        d=google.com; s=arc-20160816;
        b=kyTcx5O4Zdbmw7AugrVGs/c0kHCZu8+LzrPQNcno9D6f/Qiw5pRmwKkzQ6fGjclyvx
         Jf23wNtjpzHaB4hm3fxdIG6jztzquvG9Eg3zSgGbkqOssKTIseFHaC6IYQOE9d2mNjDm
         erLusODdRa12n+5PuWw8h3cNGzTPLjH7NmJQPWNxRdLtbA7lk46ngTfWf71ZqoJ9h2Nw
         uIVlS+A67VdJfrwAviftD+lFUfPe7SlnaA1nMujhocS2Mihd6fk7oGqZ0hd58l8DO9oY
         ysbg/kaJw1gUkIF2a+Bw3ma8I8aqB5b3Tv+DkD28/lt+p65+PLhLEYXDbzPRZbMkJ2vB
         h5Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=z5TS0hqgTw7se9Bs+Ko8uWgoiCZL9FEoL58vOkUGJ/k=;
        fh=U8oyG0PSLbVUNpckz97q+aRwsMuBPpMWzQ6khANKKFQ=;
        b=uquFYoI08Ox2mKlYFf+IPFWh5Lhi+It5blhEKR/HlOSqghpyENO/ujK97K/zw2Uolq
         9NzPAF9jTpsOHFt4cQbWfEjGNjbzPe9Qg2K46vLDn3fAMMSSoVUhdA1+90Q5zcqOZghH
         TVyF3tFF2TQ46ABK3t6SBGfTqFiP//IAl9lWZVUzTrcI9yQpQseW84tmc8IHOhADApbI
         g7lSKISXKLm8nLuK7JgR+HZvIoeym4AXDHRFC5Et6up55hfteIVS44IhG3wOvXs5cl4N
         Vr2uhRS8awpzkMjMhWb7PSHuDxJITE/YS2H7YbksucdLobjnhFahazY6FB/vVTIwy/UX
         arOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=cs7GGt9a;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=CaMgsam2;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708015505; x=1708620305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=z5TS0hqgTw7se9Bs+Ko8uWgoiCZL9FEoL58vOkUGJ/k=;
        b=G++ziqbTWFfU2QERTcaN69BWAfL23SL1Q0D7H6xwpCQ0mjHM/M7GU0N66nCViylUO0
         lDB29PBLon0Q98TSL7A9XROpA5yvHOejMNr7i7EdmN0jp5lX5htPQ6ljl/hUe+SEW8qS
         AlqW2Xt1pkzAGBPsEU6lCRkg0tRw/Wk5e0AepFBkN5AhTfkZ5aWw40MoOzEvC4qYIJPu
         UyjAr+YXxjOu6ot3CPfgjIs9V8uOW0+uMSC3z5Zk+dYdUW4eP9sDUQJvZkWcXqHSp6em
         YxNeLoTulHbQ9c1jscs6DEZCFH/S5JW/v8RPvGvlGy6yw83Piu5OkwVbUkAwj76RgqPX
         GfdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708015505; x=1708620305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=z5TS0hqgTw7se9Bs+Ko8uWgoiCZL9FEoL58vOkUGJ/k=;
        b=E8pwMkFp0BAfKrNSHcIpxvGwsCR0be5d7hQJrnp4usIwcQivBkZdOpr1gHUcn/Emm8
         uKZE6O4VBDpMJE7ViTnUA7L9fYS4aoStTZHZO0pQdYNdYISpnyLlFh835gJRrmIDa9VQ
         pDc42dkNIUnIS/fJV7wfbqHSyQ10If/+8kIj7+WbouI0BHc6UIuHPjHlvpvpmu7lQ5Hz
         Xv/OgXaeRA3FSXUuQ1lX1KPBojnQqGF1+Rxuw4IyAcUauMbO0ZoeRP5F8LGFPJazs/Nh
         tIxb6lran3nFViBU5rNNwoXghVHr2/K0ptw5ULONRpbE+5eBQTtTzz3Dve8ZMqkpUj1m
         Taow==
X-Forwarded-Encrypted: i=2; AJvYcCXIgrEHletNBLD05WHZilewZMPBh3MnBdpSxGLF6m0+emQ1+4KvoDYVP/CwA/mQhe4U6ic41YbJwFmb2T6uKEpvbIdpIj0bNQ==
X-Gm-Message-State: AOJu0YzfrcdKbLWSt3oS8n6seqEeNNe2w5tew1C8qAS0veDY3l3MBkyU
	WjxZvNXOBdsU0lcNA6jqj2tUmCSGRrNsOuuhBRhTOMR16td+885X
X-Google-Smtp-Source: AGHT+IEGC7SNTmQ+zx+Fa+5EXI/NooxCwelLjUyu9eiCwAS3aHXBaV3Le3ktdMMqgZG1/mDr1YOXIQ==
X-Received: by 2002:a05:600c:3d9b:b0:412:255a:f7dc with SMTP id bi27-20020a05600c3d9b00b00412255af7dcmr13150wmb.5.1708015504779;
        Thu, 15 Feb 2024 08:45:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6019:b0:412:db:57dc with SMTP id
 az25-20020a05600c601900b0041200db57dcls474458wmb.1.-pod-prod-06-eu; Thu, 15
 Feb 2024 08:45:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKbOwlpvyHKqK9XLQ0fQZ0pdTk7IM93CClCfeQf/u9niDy3+zsCGBf/pkLQH++oUDQUjlRgt/Vhb7phwaTgn4IjnZRdik1KWNUqA==
X-Received: by 2002:a05:600c:1d26:b0:411:da90:89c0 with SMTP id l38-20020a05600c1d2600b00411da9089c0mr1921497wms.10.1708015502713;
        Thu, 15 Feb 2024 08:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708015502; cv=none;
        d=google.com; s=arc-20160816;
        b=zQdeIPe8f/QctypaAjuerPccV6PvDMPscfPhNg0DNiMblvsS7a2mz4MDxfmJDkDKvw
         Dyp18T3HNMe/JK6PivKG2PPEO1bylzWvorJXza10+OqJRoAaJXq2dA7eduwiDvqXPGI2
         RC2ODYBiiKMbE7nexCWKmZJLYs4Pd+j0FrcsbeBJmJmB4yFovoo/Ff3sjcQbmHz7UEe+
         rYm0e4WLE6uwg2+oM9wc0/L/Kx/M2F+6PMKx4paOwv/3k/D6lO1k22eWJEH70cYbF8b6
         7zt510QeOAj8sADvVinkyYpPXFCRrPUt6UJNtYYVyYZmtmOwWurn68iWwop4m72MWDea
         Sc9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=VRHpwz0jmcW35D6Wb8el2YM1B2vf23RXP7/FUXCRfsQ=;
        fh=Ogq5Bz4Zz2qWMySoXrNTmv1uJW+gTwbteDGCKK45UbY=;
        b=ZXl8wbod1Nz8t/57xJDaQEUqYIZ1/2QbfZqRdgo/V9txWxvW7PLoWoOw4+R0xe8VtT
         j9sP9qLLIXJZQlXONEm+xXK/Mcigt8dYks0Wds3tQK//p4660xTEGBsRdL+8tk8/M7+L
         9dAP/cJkHtDrpZiFKH3/dW32eMzg6nE0nwOcIC2dKdu/O05XPrkRrgR9c+92UhSpvCHf
         85Y8I4AMpUe92MtUx7/qPr7zmh49IH6qjHba4DryeYsdDlshl2EgjxBC0rKVlvdRSKTC
         CjfK5MOOPfNqNJ31qCqCW4/9dPpf/AC5EeW6l80Akrks0X8eKVsC3CHxKr3EBSFKMV/s
         uZ2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=cs7GGt9a;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=CaMgsam2;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id r14-20020a05600c35ce00b00411fc619abfsi114671wmq.1.2024.02.15.08.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 08:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7CCD21F8BE;
	Thu, 15 Feb 2024 16:45:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4C44713A53;
	Thu, 15 Feb 2024 16:45:01 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8HpaEo0/zmW6CQAAD6G6ig
	(envelope-from <mhocko@suse.com>); Thu, 15 Feb 2024 16:45:01 +0000
Date: Thu, 15 Feb 2024 17:44:59 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <Zc4_i_ED6qjGDmhR@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
X-Spam-Level: 
X-Spam-Score: 0.70
X-Spamd-Result: default: False [0.70 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 R_RATELIMIT(0.00)[to_ip_from(RLibijwhxa4crtso4io181jfzy)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.cz,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=cs7GGt9a;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=CaMgsam2;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.223.131 as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.com> wr=
ote:
> >
> > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > [...]
> > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemask_t =
*nodemask, int max_zone_idx)
> > >  #ifdef CONFIG_MEMORY_FAILURE
> > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned=
_pages));
> > >  #endif
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +     {
> > > +             struct seq_buf s;
> > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > > +
> > > +             if (buf) {
> > > +                     printk("Memory allocations:\n");
> > > +                     seq_buf_init(&s, buf, 4096);
> > > +                     alloc_tags_show_mem_report(&s);
> > > +                     printk("%s", buf);
> > > +                     kfree(buf);
> > > +             }
> > > +     }
> > > +#endif
> >
> > I am pretty sure I have already objected to this. Memory allocations in
> > the oom path are simply no go unless there is absolutely no other way
> > around that. In this case the buffer could be preallocated.
>=20
> Good point. We will change this to a smaller buffer allocated on the
> stack and will print records one-by-one. Thanks!

__show_mem could be called with a very deep call chains. A single
pre-allocated buffer should just do ok.

--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zc4_i_ED6qjGDmhR%40tiehlicka.
