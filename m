Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA66R6UQMGQEYWXP53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F4C7BDB33
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 14:16:05 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-27763f1abc8sf2835317a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 05:16:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696853764; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCeFnMjCg1mrpBZsZhqyKJyLSqWh6V1kTe8h1DC3QcFWgM6Zw3toepZoSNiHqvrs6a
         VswGk2nQsjkbpx9HILvQQvBc0wpDD2JLmB5GTDOxths1T6f05VXn1BspmjMSATCtRof0
         MzBh/2iJIXn2GpO+ulLsGEqcbxmAM11G68wp9Jw11LbiozQwxzK+DG52NEhJqvXcs95v
         mU7YwUZECF1/za0B/NxnIqrxSCdb/VpEjyBMb5rdOB1Eqw3HN03m3Js8UK7KmDgBwaAH
         WrXV3H9bYdVg4/KzbdJNiXJScdSKorwcrg99kjQ2ETIeTyjSBAM+5PsKKh6JisDU1m50
         0DnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QUwXPnI1DJbf0pwYnk7KgYw977iNP+ubSEgBZb55LzI=;
        fh=Vxv8GWGH9lQmhEoAE2yCk/ylzZGDpbMQIsU7b5w2E5Y=;
        b=i+xmzzrq51Uq6+Hf3myRP2V2I/dthimPPZ2+EGtvRUTtDVTMJqeW40vDhGKFQ+Nfax
         68pxSKAJqikn1zk9U+eVR/meNgru/dEutkcPPX+QMuCXQp64NPSvuXZ4l8OTkz0uw5E+
         IR7n/X+gGkQxaz3OroTy/6FF0XaID99HBakXSX2x4CkoPHmEs61yZr9YhIh/wLJMBslq
         HN7zShsxD2HTlOgHqx83VGlgcb3cKqmuVHnwHhBq231ULmtSjdtFtZcoWeoz1sdMLuiQ
         PXa2Lf8hX1MMbn7eBCeLI30rQPg9MWAJwMMRd5FTtU4IK9RiznXIGqbTDw+LHq6xj60F
         YvWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xF0TV4YU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696853764; x=1697458564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QUwXPnI1DJbf0pwYnk7KgYw977iNP+ubSEgBZb55LzI=;
        b=YDxAP2SCIfobpKnn4ywnJwzhrrqVZPY5QfdhgLKvYsEg1GLJcQ/A3K2oAlU6AmaXI/
         Kq3CqYEpSoU6+QxPcIS2ipmoxHR19oXa8jBT7BfFvXb87lSKxMbcTqF2gNTKpguhJBri
         7OB4NA4NZ3iRDHP9ATjmhcYESnwLWf77Ug1FzmW+iiM9I/Pp6Qx/tkSUCehEyemmPACK
         LXysWyKAFowOMmYMDTf/IC9LdwUTWv4FpdkXrgDuvddPPIikLAgaW3+SoS0hLJ+APOIr
         giwbNMHs+QYdIeVh4QVYN0ePlYhsaeaODZ7KJszrMjTKzpcnVh/gDXrLagV8hELLFJbM
         HQkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696853764; x=1697458564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QUwXPnI1DJbf0pwYnk7KgYw977iNP+ubSEgBZb55LzI=;
        b=SWSCRZfgcQUiSiC8cV5epY/913/bOy6ecLMULoMMXra1ReQQCgDCbG0+wIWnDghytp
         SEifd8POvn7l5Q5sImpvcFKqAzUlYFAlRs8nPiLAykVAnkl49PMv7t8pWhanMF8dt8QE
         QuR81iImj+ckzg01XCkJp5fOp9jfvZaccnnXRh7RWtTUkLutO7Ij+i/RzQVls1h3TpUn
         6oCLeI1794YmI8mJqnl1O+dj4nF8ITIivV1Xhy4S6irqYZr5Wte+U1D7v8fnmgGgom9B
         8Qt9CuvnRnSOrqHNJJLqYyYer9NQrsqr47BMr8lCdha2Ub/lxtulF39X/gumMNPOqWEt
         zUQA==
X-Gm-Message-State: AOJu0YyP05Ne3J6nnxEvUpacrPoEngtMKDjVtWC8TLrLVgjfyVy+7BMV
	w7bTbZCaJllfeH/d5RlaBlE=
X-Google-Smtp-Source: AGHT+IHaT5q6Fe3tXMzNjxoHW5AngpTXSRovBpv29XRaX3Uz0dePERa57kywWWdi94tzYu/voxZpIA==
X-Received: by 2002:a17:90b:4f8c:b0:26d:ae3:f6a6 with SMTP id qe12-20020a17090b4f8c00b0026d0ae3f6a6mr11446634pjb.18.1696853763470;
        Mon, 09 Oct 2023 05:16:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:23c9:b0:27b:168c:afda with SMTP id
 md9-20020a17090b23c900b0027b168cafdals2065195pjb.1.-pod-prod-04-us; Mon, 09
 Oct 2023 05:16:02 -0700 (PDT)
X-Received: by 2002:a17:90b:4b86:b0:279:e5e:ea1b with SMTP id lr6-20020a17090b4b8600b002790e5eea1bmr12861050pjb.5.1696853762502;
        Mon, 09 Oct 2023 05:16:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696853762; cv=none;
        d=google.com; s=arc-20160816;
        b=uI7+rEiw6tM41LQuPOn9Q22BAWNQ/1Kc7fKlhSYD3Kkr7ai1jxliS4kytMxx0NBQ/i
         QCcJiqISX/aOY4i60Qs/BBsLyjUbyU+aIcPh7guawki34B0zZ3fo78IQmDn9pggnn+ny
         3Vpek+R4OGUqPj5WQP4jzmgQk88D+an9bBbNIGoLgmhVPfewpAiEjrOtW2ptoONfEooF
         boJep8yRWRCT25ioQza4EJVmXPq9HFiDJlmczaTeSsvRoBVGywYAI9OqTVPv345d/+2Y
         BvcL7x4ZBz0ViCWJBUa7s4F+mWY9Gy9FRPREpBxcpyEhlJGgHFp5jZbNdt11NKXQZCAL
         P7FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iw95tEeWB9saYTjeuqfwDCk67AfASMwamONQ4Q2lXGY=;
        fh=Vxv8GWGH9lQmhEoAE2yCk/ylzZGDpbMQIsU7b5w2E5Y=;
        b=OUF6RTbonMkMcLHV+2mYfuw6ad0D5SQiG1L0ssvDq1qdZtj+EB6b9ogLJhv+CJ4Fq5
         PqKwdauzBlxz7WX/Ys04EdEwoWNwaijq2u+Ll/YygLpVTOchPq5pI/bLN6K4J18Dnd9k
         uCqXufQXzSpg1Xkriw4Fq9Yvm0lcy64voylI7D2ceK2V1K8pQRlf0vnS8+qbLds/UCDh
         Bc9otdGB8wYIGLIit/XfX1dWPnUv+WN3ZMLa6HS7NDuQub17lzob1S9VXgnvdx48fYf0
         EILHCnfoV/eGEFu+0Tfh5JAK0M4JW1PyE5REGFqIybOXNJHd5Ejt6sNFFeWeawxQNthD
         LiHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xF0TV4YU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id pw5-20020a17090b278500b00276a78ed402si557792pjb.1.2023.10.09.05.16.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 05:16:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-65d0da28fa8so27420706d6.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 05:16:02 -0700 (PDT)
X-Received: by 2002:ad4:55d3:0:b0:641:8b09:98ac with SMTP id
 bt19-20020ad455d3000000b006418b0998acmr13512054qvb.37.1696853761812; Mon, 09
 Oct 2023 05:16:01 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <d94caa60d28349ca5a3c709fdb67545d9374e0dc.1694625260.git.andreyknvl@google.com>
 <20230916174334.GA1030024@mutt> <20230916130412.bdd04e5344f80af583332e9d@linux-foundation.org>
In-Reply-To: <20230916130412.bdd04e5344f80af583332e9d@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 14:15:25 +0200
Message-ID: <CAG_fn=W0OO4GGS0-pnHFpnWGsBN3dZJ9tnRxPmEKRkkP4Vh48A@mail.gmail.com>
Subject: Re: [PATCH v2 12/19] lib/stackdepot: use list_head for stack record links
To: Andrew Morton <akpm@linux-foundation.org>, andrey.konovalov@linux.dev
Cc: Anders Roxell <anders.roxell@linaro.org>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, arnd@arndb.de, 
	sfr@canb.auug.org.au
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xF0TV4YU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Sat, Sep 16, 2023 at 10:04=E2=80=AFPM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Sat, 16 Sep 2023 19:43:35 +0200 Anders Roxell <anders.roxell@linaro.or=
g> wrote:
>
> > On 2023-09-13 19:14, andrey.konovalov@linux.dev wrote:
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Switch stack_record to use list_head for links in the hash table
> > > and in the freelist.
> > >
> > > This will allow removing entries from the hash table buckets.
> > >
> > > This is preparatory patch for implementing the eviction of stack reco=
rds
> > > from the stack depot.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > >
> >
> > Building on an arm64 kernel from linux-next tag next-20230915, and boot
> > that in QEMU. I see the following kernel panic.
> >
> > ...
> >
> > The full log can be found [1] and the .config file [2]. I bisected down
> > to this commit, see the bisect log [3].

I am also seeing similar crashes on an x86 KMSAN build.

They are happening when in the following code:

        list_for_each(pos, bucket) {
                found =3D list_entry(pos, struct stack_record, list);
                if (found->hash =3D=3D hash &&
                    found->size =3D=3D size &&
                    !stackdepot_memcmp(entries, found->entries, size))
                        return found;
        }

`found` is NULL

@Andrey, could you please take a look?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW0OO4GGS0-pnHFpnWGsBN3dZJ9tnRxPmEKRkkP4Vh48A%40mail.gmai=
l.com.
