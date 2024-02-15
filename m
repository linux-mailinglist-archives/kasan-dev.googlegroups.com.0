Return-Path: <kasan-dev+bncBC7OD3FKWUERBMGNXCXAMGQEXY6IEMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 74EE48566A8
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:58:58 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-3c045048e0asf784335b6e.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 06:58:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708009137; cv=pass;
        d=google.com; s=arc-20160816;
        b=aTENP3Xurl3RSu2d9M3CKi4jOnYb3l0Aveaaq7Yv9Mr6ikjAO1GpPhS0nrcM3NwO9L
         o0rIZoeVUFbgMeB61kpIRWkW1smIWAJ6xRKu13BWBd4q+/mgy9xB3LaUpfSKxptNu39V
         Bg9KIgWkuJPgkXRr7r+caKHtN80wN2/iw3zJWh63L1xJcp/CUmVGRM9oC8DalXtq1YJO
         s/TU2q/Xrsb4M6w+Q7qSJHhC6a2lj9dhMWdx2Br+RcjZ+P5ZUq6OdIKDstzoYNu9oJUQ
         mtfS4w3aYsiB59cR9WRBPXhBVFQq3+Bho9gkq0LTFcilFN4XdONf6AdYL1NFk9dJCptc
         A0EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G9IPXuN27lKNMXUhGRCZ5Q5ghzNPWlP5yWfG/OCCExY=;
        fh=l7cdk56pso8HNA0JVhEdzSOuIcl5F+Tx+pxd8C45U4E=;
        b=asyfdIjeDnfEEanZ2LkTpPhyiafApOXgCTT+oiFMnaYLM2nDiF7EkOcFR148j3Ial0
         SjmxoZhtcyShOwHtxlw4v3yczNcT3/j2/XA2/HLf5e33IBCN5BUThlOnvyYZoEYChmcg
         2HWqfDNadomEuKQoOsjcMX5TchjK73hFMu72ZOANBurvRt0FZVjo3ecsDd9N9Tdwxz63
         UZP3smRwVJ7M1KKje8cTXw1Aty2QtV9lLB3S9SBstQDNDdL233xONn1i9IxWx0Z/VYZ3
         TWURprlXhVjvH2j84J2U1Oi8AsM7hpSV6+PSshaGUMzOIhgmMIime7PhQjDI50Xi09rx
         PPoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pz8wrkas;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708009137; x=1708613937; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G9IPXuN27lKNMXUhGRCZ5Q5ghzNPWlP5yWfG/OCCExY=;
        b=Igy+1tkQsgY2F+hsCZ5Da5EqCH9bTOnCuOw1M/U4984Q87Pdh5JqsA7lMmyXK8uYcf
         /TzSlhUDaX92HPY2MrzHi06imlfNbfukgm09kBj4R5kBEViwpaNIAh2c9z6CR0vzn4PE
         NEs5nk0gi0VUwQCi9K7ST5J+1Z6pVLf6GqJviRYqureVRJAlm8aNx+TpH3gz5aod1Bc0
         jxmhrvDnprbmMtXhON7oTSsU/4JcpTeSz4rhdGYrnU4kKa2TdGGIubkBwo6+YV78AeDN
         UhBzE/CK9FGcKDcsyCtl0Z13jyxXxM8kRU+wkrmW/BJVG3s5ICTJgAc8j3HK23qUvcVL
         rQvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708009137; x=1708613937;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G9IPXuN27lKNMXUhGRCZ5Q5ghzNPWlP5yWfG/OCCExY=;
        b=YRjmj1LsjAAeQyDskgKjKZ3G//2Swd+MctC/SjOUkwZHaBJrP6ET7rfyto+pOB3k4f
         s1Yqoiw4xP9+sd9EhlxcZ032Asn0sI0pmjKbH+m+L00zsmv54KohaaEyUkR9Z9meIqjh
         ah3D+ZJMIzxxsK56fRxIPK4sGhYxkYo7RR7ieo2Gq2eAbpQtQ4bKabbl5b0LjfW4gJ7G
         EBJJCDJ12h8uS3ek8yP7Q/EgLzuOESKjEXEKaoTDKB6azPcf7H2ahQVg1mHoMj5HBtBo
         /wUVHSTX5WhM6o7Ax94ispN0HRCGB0kEbIM6BX3yP99HPjRJhnwWVf0Vz2mmlag7N7nb
         lDaQ==
X-Forwarded-Encrypted: i=2; AJvYcCUr6QL1YZEYSUrExcUXhmzJmVwmKOWsW1I9awAoXLwondu/ICt/fCDUfsFjpGfB0wq70BW8PMY+H4x2NEcs5DBNJsjE0rXCFw==
X-Gm-Message-State: AOJu0YzqQ4OxpxjhfFQWW+Ty0mRNDuYnu8+d0boGHR4GxWrq5l720hAN
	MZv/kDTtrtbZHn0cbkGMSwL0jKf051WMm22fu55Y8QRjvogq5sLp2vE=
X-Google-Smtp-Source: AGHT+IGg3WnZ6MDZaOApATYrdWL6e3rk44Pz7UDibCc1niLS5Ti9hyBmtZBRyGtSZEHgkHCpL3di4w==
X-Received: by 2002:a05:6808:5cf:b0:3c0:30af:16cd with SMTP id d15-20020a05680805cf00b003c030af16cdmr1920695oij.50.1708009136968;
        Thu, 15 Feb 2024 06:58:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d45:0:b0:42d:b27c:d99c with SMTP id h5-20020ac87d45000000b0042db27cd99cls3071247qtb.2.-pod-prod-08-us;
 Thu, 15 Feb 2024 06:58:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeLBbgS0/Tl4Ew2bI2QjRY/8iKHOZATBnPwnlQ54b/F0Reu/4uoxwYCATL7IiwBMH2Ern46IpVb2+AO6k62xePAZ5+/xl3eB3tdA==
X-Received: by 2002:a67:fd47:0:b0:46e:cc9a:71f5 with SMTP id g7-20020a67fd47000000b0046ecc9a71f5mr1633993vsr.31.1708009136035;
        Thu, 15 Feb 2024 06:58:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708009136; cv=none;
        d=google.com; s=arc-20160816;
        b=fBTLLleAnts99LMXpoFaUMGpDMo00YNf8lGjTIl/URAIQxNjw3VfcU/t90JVqvKYve
         7T6pa8Vfy5E+MFthkqjodbU/NQZwQQmrOQ3DMJ/XQme1xwQe861k/gcAWbHJpHoCqlKo
         MBLOOctykdiCVo3Kv9TImau+d1z5qDQPGIkJT4Q9Hx/an+nRt4Eh0MZMfiJBfe812qpK
         XuxUs5F9NuC9e86P2LmmAg0IyEL4xj7o0o8khoBrRFkGMVo1GaMqE3KbRtlPWp78yNy3
         LA+cA4ecsza31leLyod97rwu1lBskRvwvIdLtGLOFRm0PbIEFkh0dYaNHtPKn9Zmy9cO
         liYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Tw/wN6EwhF1l4GL2nZ/ht1qejqJOWh5ecVMENBzDBDY=;
        fh=rM/PAJmfwEe+BFOdMBkEg6gi0T5FOi3o/CRB+p862Zk=;
        b=nL8pAX7OFtoyFQwZowOJ7P9mHH8pCeFBVpZr5vYS0pUv3MfxN/ozQovV2ww3V36daQ
         zSyQ+70p+WWWLqXO2sAT6r020FIxs/xBzy6d8lWcWKPaLuL6jE/lv2MlLSREid1787Fb
         um7sNpahoJzrdlpRz7bt8xbPMmdmoa49VSwuqJw2Nd9quOtEk7ga06LrNmnv0vUlHTfI
         EHTztRbayePyHYQP+/UIxpAARfI4fIZ5OSO1X3jvZ4/Bg7KPl7py27QgZhlSVn/7GeX1
         pcwf87wnmQMr+ur0hMWm0MjNq0DoAweZqDKjrx07p2l6rWvkNtwTj8JBtXulJnRBrgv2
         7Umw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pz8wrkas;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id ib25-20020a0561022b9900b0046d3986403esi200989vsb.0.2024.02.15.06.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 06:58:56 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-dcbef31a9dbso664658276.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 06:58:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXued+8OyAZhwc5/1zIPr9bm53LO4FPOIHCV7NZKd+NoIIifEpUwjx70/HTKRGYLGbgQFPJA03mDK1J59kja36LsR8AtyUbMlMmXQ==
X-Received: by 2002:a25:8750:0:b0:dbe:9509:141c with SMTP id
 e16-20020a258750000000b00dbe9509141cmr1821330ybn.30.1708009135319; Thu, 15
 Feb 2024 06:58:55 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
In-Reply-To: <Zc3X8XlnrZmh2mgN@tiehlicka>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 06:58:42 -0800
Message-ID: <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
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
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pz8wrkas;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> [...]
> > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemask_t *n=
odemask, int max_zone_idx)
> >  #ifdef CONFIG_MEMORY_FAILURE
> >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_p=
ages));
> >  #endif
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +     {
> > +             struct seq_buf s;
> > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > +
> > +             if (buf) {
> > +                     printk("Memory allocations:\n");
> > +                     seq_buf_init(&s, buf, 4096);
> > +                     alloc_tags_show_mem_report(&s);
> > +                     printk("%s", buf);
> > +                     kfree(buf);
> > +             }
> > +     }
> > +#endif
>
> I am pretty sure I have already objected to this. Memory allocations in
> the oom path are simply no go unless there is absolutely no other way
> around that. In this case the buffer could be preallocated.

Good point. We will change this to a smaller buffer allocated on the
stack and will print records one-by-one. Thanks!

>
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG%2B2XNcc9vVmzO-9g%40mail.gmai=
l.com.
