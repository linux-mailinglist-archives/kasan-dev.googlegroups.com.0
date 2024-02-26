Return-Path: <kasan-dev+bncBC7OD3FKWUERBEE66OXAMGQEOC77J2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0281A867F39
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 18:49:06 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2d251670e72sf22471461fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 09:49:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708969745; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCn+NukstgG9K69KSqWqxkER2eeHBjLcuzfuEbTB24re1oNzL6B08GbGiOIwu9KjPh
         t5RI8IrTawpIQTWydoQyvvGqH2NXnQdx7gdOr+8PekCP3B3XFelzZrOSkwyii2iT6J+U
         ZjY3IUiFgfwEyKnQHHTZpj842KgYwTQrqy0JXIHTygX0Fi/Oh3bENGZN76C6Vcqvvc1d
         FQkuFxfp10k8je5QqaNBTHtU0aNq6xs70Zs0PFh6f27ngaY4uJminfTBt4jHJdRcuc7S
         AQzO43K2+wOkkoWZZb7bB02JNun1YLum0zvmzgaDbLXBqiJ6PE0R5sba14qzGLC316bR
         v79A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uTd4J4nuoDJeaqInWGiop1F7JbhUQ+nBHemGdBKYvVQ=;
        fh=owJjFT9wmHc9N4PWjo2UiLaLLhYT2g6LKLpFH3kDOIA=;
        b=rxQAiiSaK3GP12YqoqlE4uNrCPlSYAGo8kcbFRoIC5QS2HXlYB5MZ5/0bEUi3VoVp8
         zrpCmXVUw/YbFYy80Npb/csDYK1yyNfVbKTidBhj5WxAcpFGMizIOoY2iskJOzAW4bSQ
         lgSHjpfIpHHxHKR/bThIf91VLEdPDiTKbvPGDObXrFBhelkhNbYSczz5z+QGP8mYzfvs
         YFPukw/Rw5bWONOlrthWX5PAfjz5cugrJG8fbWh/3MRE6tc0mHR6JKd6LTFDSyTeF6tB
         nxqrVB5Q9S2ipi/gqBXxyWEpPIHvqa2k9xFBiTcJXjvwO0JLNrcZP+AItKtu+QUkVRxz
         6ing==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4MEo047O;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708969745; x=1709574545; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uTd4J4nuoDJeaqInWGiop1F7JbhUQ+nBHemGdBKYvVQ=;
        b=cXMneqoR8YrT00Va+T/CNbzF1Vxutk+YQIx9mU4EmId0EWjIxIZqDBhO7Qk8hfJZAH
         B09C39tD+2m8RwmQF1qzhjBE2ebZYACTT8yL5KaMZB7llZYjSDgHofMFCZEm9a8Auvon
         tlezaaF2+P8x7YqoFoxpqrNxr+pg9ZgMXWojaDAUNGfGsAkkibPaUwHufvY4YimLq63L
         1zoBEbY+XFpfIwQNQRdHptcONx1oO98Q5PNiwEtFeO07lAM0SpR1tywLos+NEEryQIg5
         Q0WkaudpRmnwjGJ6s0NHONK7dMEd/OybbYcAth43J2kdcdW6rIwE6dt6m1Lr/DJ7OfVk
         7odg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708969745; x=1709574545;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uTd4J4nuoDJeaqInWGiop1F7JbhUQ+nBHemGdBKYvVQ=;
        b=CUTH7MoeQRrqLahN1gFryZ+wHYrjstd4EzuDQVvJpsjAMKP782Dh2qkDjTZWJ4gG16
         QShgbbKOXMQuaP56RKtxB3VTWkLlzN/CDSgaFvwGSXdkNCTdAjOs5XjMHY4myX1NI4Gi
         /jt1wN8Rs+LGYjoR63q3aSaKlMsptT2gkFUqyUf+BJkrlZ8je0HEXjgGhwH6ro3EBrXU
         nudRS0HuHYklkhxzNLpSAXVuBeTgPJhYP+EcFaheSyfZWKaYX2V1w14iSkg6K6y3WOEn
         OSwhjLEP8AVH79PoG9C54S5wkbtiUVd3VpUBkNjyXlV3aTFLjGBs2nGsMfKnShIVT60K
         Dp5g==
X-Forwarded-Encrypted: i=2; AJvYcCUKM4LDUBPaf5Xaiw5atWw5I/X3FTyQLiNMBDxXWn2IWgA1jD/atIUBV3uM+cLAxxkX/rsLwhtb195j+bI+aF49+b+yDe3DwA==
X-Gm-Message-State: AOJu0YxW1jyVrNp3wExJcsrvnwI6NN1ti46rXIGvM0JTi/0P8pLXXwv2
	pLK0QePPiJ06g/anz/cAJfu2IQyrJ8BHO57Rq2pEkQBLNOzROniV
X-Google-Smtp-Source: AGHT+IGZEw4XKzYjC/vYK2QtDzLvRWC7G+B1TFMx8Lq5P1PYVMWgmQhbweWQ2AJc8ZOaxrcvtdzY+A==
X-Received: by 2002:a19:ae0b:0:b0:512:b78a:1b2c with SMTP id f11-20020a19ae0b000000b00512b78a1b2cmr4350452lfc.22.1708969744647;
        Mon, 26 Feb 2024 09:49:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3da7:b0:512:f2f5:ac6b with SMTP id
 k39-20020a0565123da700b00512f2f5ac6bls96655lfv.0.-pod-prod-09-eu; Mon, 26 Feb
 2024 09:49:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVvJJi89n+am0UQUSbCiyMXDipqWw89NHP48HRNdybogz/Ngb1U1h9yLGOr1cP2ZavtxKPIiNkYUXGRKOyQaBtlbyoLQ1+cGdHqQA==
X-Received: by 2002:ac2:4203:0:b0:512:ab3d:d551 with SMTP id y3-20020ac24203000000b00512ab3dd551mr4892976lfh.19.1708969742730;
        Mon, 26 Feb 2024 09:49:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708969742; cv=none;
        d=google.com; s=arc-20160816;
        b=gx+mzotnooaHmvmjFPhfiezy1fiYmVETao4JpQv22nFhH7/f2lb5bwxs7pXHKFA5aQ
         vsd3hYf6Jh3ZCrlAoyr2wQIXO3dzODoRbEUxYhS0iEHc+upCJKa3tX5ZOBzZ4zTJJcUP
         99kleFuuRUG5Us/0KzLanAXOUPCcWbwKJcroRuLF1mUesTvwRlt9oiURKgTWeffToijr
         TROJvcPegwkLI+6CrLqxnxgeA4ELiktlRhKS9MuCSdGrd2GBkX6JZHAoGs8CLbYNdn2r
         Paxmpkp2ru/aFv2Bik7sIpwz4b3Wz5E2qqBW3HHkM6AE20upDdXXFeJm6fa9XRYRIwaK
         VKMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=E2MfOrnw8vcrCKgg1+LRA9aXdiQ7KcRVPoPiOl2oNZk=;
        fh=J+PxrR4fgtBOBVGgUasBXOASb1+rEyYCsS2xtcp+u+4=;
        b=MCr+2PsYqpVNBZv87R/9YKKVCC6KTiLKVpJJzFFBOpP7rOiHJrLaeg3gBzBncoVGzv
         ce7CS9kOGEXOIFWphF2lZdhEklN3YdgXo8UTJsDSpUWCc8iWha6dOp+GX7w1/Fr7OJNk
         t/JT/XwC65LxF8ht1aZ2pgqDORuzTsQtgMq30zdJMIV3jk2Mbeb5oEoX6fuBbDmRcYk1
         pIOLF5oa254VxeXiH22Im9xvfeQseBSKaQUFdXBdRPnDXqYy6SNNhDbYJCZDGy9Zw8mJ
         S456qgdL96q5JG6O3ObxNLnBc/fCqg9wgheU/82zsdaXjIZVmMM6wV5lIObGOWZGdldW
         24VQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4MEo047O;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id bi4-20020a0565120e8400b00512f3dd861fsi370512lfb.9.2024.02.26.09.49.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 09:49:02 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id 38308e7fff4ca-2d094bc2244so39060021fa.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 09:49:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWdg6axhUsIarpDAFAlcHOgKIy24AZC3t363zs8YnLncEpibp5lV7xXoSojydHpMI72qGaJBkH2rdKQalxpCARjtPV1KWf4uaKSMw==
X-Received: by 2002:a2e:b889:0:b0:2d2:6676:3b0f with SMTP id
 r9-20020a2eb889000000b002d266763b0fmr6282519ljp.22.1708969741996; Mon, 26 Feb
 2024 09:49:01 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-6-surenb@google.com>
 <f68e7f17-c288-4dc9-9ae9-78015983f99c@suse.cz>
In-Reply-To: <f68e7f17-c288-4dc9-9ae9-78015983f99c@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Feb 2024 09:48:46 -0800
Message-ID: <CAJuCfpEQPgg6-TD+-PEsVRXnK=T0Ak6TvMiwz7DbS-q9YxsVcg@mail.gmail.com>
Subject: Re: [PATCH v4 05/36] fs: Convert alloc_inode_sb() to a macro
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
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
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4MEo047O;       spf=pass
 (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22e as
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

On Mon, Feb 26, 2024 at 7:44=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > We're introducing alloc tagging, which tracks memory allocations by
> > callsite. Converting alloc_inode_sb() to a macro means allocations will
> > be tracked by its caller, which is a bit more useful.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > ---
> >  include/linux/fs.h | 6 +-----
> >  1 file changed, 1 insertion(+), 5 deletions(-)
> >
> > diff --git a/include/linux/fs.h b/include/linux/fs.h
> > index 023f37c60709..08d8246399c3 100644
> > --- a/include/linux/fs.h
> > +++ b/include/linux/fs.h
> > @@ -3010,11 +3010,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *i=
dmap,
> >   * This must be used for allocating filesystems specific inodes to set
> >   * up the inode reclaim context correctly.
> >   */
> > -static inline void *
> > -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t=
 gfp)
>
> A __always_inline wouldn't have the same effect? Just wondering.

I think inlining it would still keep __LINE__ and __FILE__ pointing to
this location in the header instead of the location where the call
happens. If we change alloc_inode_sb() to inline we will have to wrap
it with alloc_hook() and call kmem_cache_alloc_lru_noprof() inside it.
Doable but this change seems much simpler.

>
> > -{
> > -     return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> > -}
> > +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache,=
 &_sb->s_inode_lru, _gfp)
> >
> >  extern void __insert_inode_hash(struct inode *, unsigned long hashval)=
;
> >  static inline void insert_inode_hash(struct inode *inode)
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEQPgg6-TD%2B-PEsVRXnK%3DT0Ak6TvMiwz7DbS-q9YxsVcg%40mail.gm=
ail.com.
