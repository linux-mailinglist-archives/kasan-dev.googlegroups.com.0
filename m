Return-Path: <kasan-dev+bncBDRZHGH43YJRBAO3VSXQMGQEYLQ5VXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 04C58876743
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 16:23:47 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2218e929fabsf1412401fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Mar 2024 07:23:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709911425; cv=pass;
        d=google.com; s=arc-20160816;
        b=JglZVjLGvTsfbvFeudRT/ipknokTGXbPmOH0rem649amxksP2zQJbnxchiXyQ4CXmH
         FyZWSHS4bJ6ZC5jWWuD3toj6QIagnHuOq4YE/zOonEVJLUlsjFt8sUP3DuSzTBEA5pPV
         7g8YqUzQF33W5KOF+r5wZV1pXLqW22BUYl2Nuz1zA3233iNwfb+gfTtUlDwfK0V2soZq
         E4F4ZK0GrIghsYxVCnTm0o4Ga/s1J+nM2yYFfILCcV8S5zNgtuEkzqPG89m/Md7LgWm0
         a4bcP22JkbyrcvTjR554lrdVfR1cYs4eaG4l5YxPfbTF8wa+YPWwaoWYGJMwsDthD5AN
         sbMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Zr674C0f38Nlwp+m/1eobyCuilgNfX9DPA4cEwRN82I=;
        fh=x6TrmLkNOLyILbQF353XYE4lRO8pG7OO76phcHQYges=;
        b=zyf1XhAaPrBOfFOEsrXbuJMohExopnZbaTDBVLSaEAZMb8T8whpu5LFMInd6p7uDMB
         2ehQT1BW6c8JPL/zIIfniB/dijx7Kt+sa9FP2iAgNQZ4Y/A0MchezQ+GCh1TvVZ/I1Ls
         aBt0b1eDy4jPx/9Ct8N78bHqzDXp8sCkVzp34bsqKZhp3qMGBM3LoYsSU/FnnnrVsyes
         R9Y2mf0scf12N5w0jVg8d5v9k7n6cSnFKamOeJ2+MOv1HlOLLWdqdBKdRNkn7N90gsM8
         SHlHVboBrrvRPJ5kxsfsoxXP+4GAUebq1sorDZiAB6XVvwQ+lGtX6f97pBdRu4iZkuY+
         2B8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QM4oFDAc;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709911425; x=1710516225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Zr674C0f38Nlwp+m/1eobyCuilgNfX9DPA4cEwRN82I=;
        b=L2xS9qvzTn+zBAT81qD6IsYdEnG8OpbLBJZzoNEF5wbA7S/7EcA89BumSOUzOmEg5E
         9G1wFTb/0WYF7yFJ+PeGkmkkwmuB7JhpcFzmz3rD/OxV3PuXdwQDpz/J+2vQujSWhj3N
         CqmYKgNv6FXmNVQdKIgAYKQKSFCbhnDA076g1TUvhdX381ystl3ZOox/xjvgDmSfc1W6
         JneCpGFp2W/ofceQsf2oHw2LVKSCGwIMlZ/Gz/BCEvhUmpeIGvcOakw2XOU0yq5fa+UZ
         yvwGNg8F4foBaOj2ReWw4Js4VydxplrPg15yP4lEmWU94zDrKhaHuM4/Vk1iQZ2W2iK2
         ZeWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1709911425; x=1710516225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zr674C0f38Nlwp+m/1eobyCuilgNfX9DPA4cEwRN82I=;
        b=NbaybJ/EEBzsJTsyhMSBtU9yboQvw2sMvKrFX+V9goMm4A6tDbkOA4ZurToiIntyf7
         i1p2rAN2J8O3bKTD+R/gEmYYeTuRd5PJkhFzZ3uUWcK6NiHBZBkBO8IcXcdPx31FpfD6
         rUyEvk4jzvJyPOGyCn1eB7RV1y6AS8ZMEH3Czm3XKznhKgz31SbD7JFGlanlv4P0mDBE
         20amsrAN8J3foHx8oyNi8LmGsGlc5VEsUM0KpsFbXgfGdCZi+MmfRzzioaB1nt956I1r
         0aNr0MBt4NugXdlzYkqbqGbJKqCUDMgHk3e3NiowEEkQdVx5sQvm3iIVdbLyXksTYvqO
         banQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709911425; x=1710516225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zr674C0f38Nlwp+m/1eobyCuilgNfX9DPA4cEwRN82I=;
        b=jMS+y0YybxPZN/JUEu6tEBNe1rn1D931Sp10fa1KdVTiG6mTcnxScA8mnXA44uU4MI
         4/a6pK4UP4YkYh8N8JjfUvd+m56gQEUrAklrFZ5ypsidDnzVRi0gTwTx7/8ywgQZLUCE
         ny5sFIpyV6HJgTXOK+pzyCif/U+8kIFx0BBS/9LPMGOhoHooHhFmlyAI4ZnOseiQaUJB
         MML3wJApKfquNFXX7nOBMWMgCYaoHuptOSBuy6q+lYmIK2ypipWV0DfidOPqwKnXuqGH
         qt/8Wt0bpbm5nL6kuRtR4Oo2na9U2vd3u1tq3XOdBj9cBTm6cN5AlHmIc0TiXoigRr8T
         1Idw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4cvzlmGgaf47roVivYjdgLvPmullcl/b+gCAfFr7IT49yz4+Tt7w2bgrYipY+hk6NcLtRBrl6Oxzp6yrnGZrjNNkXluu1xw==
X-Gm-Message-State: AOJu0YxYDlxW14zpmXGEp/lyQYfImHGWT5wpbDPTDaO4I+SawUyQTy+p
	9HP4uGdYEXyqhKt6+9hcwaCJvqiQYyN4IU8wlXJNlvc4u2+irx5+
X-Google-Smtp-Source: AGHT+IGimob/Js5HIIe7ZPlr01bfPMj26WyVWtRD4ID41i7MrG2WonFrQcR4fbHwbngeFuhUtHmJig==
X-Received: by 2002:a05:6870:470a:b0:221:8fd9:e0f6 with SMTP id b10-20020a056870470a00b002218fd9e0f6mr3511596oaq.6.1709911425530;
        Fri, 08 Mar 2024 07:23:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ebce:b0:220:4300:c4ef with SMTP id
 cr14-20020a056870ebce00b002204300c4efls304185oab.2.-pod-prod-06-us; Fri, 08
 Mar 2024 07:23:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU4XJ1dgrAzeUt/52dViP3dpJdMX+nMv4hZfKviHLv3vR3ZW5iSZE5ovWvFtSrVqmjbHbSK09rRA4QuZBbXb4OujVNvD9eQ7bxViw==
X-Received: by 2002:a05:6358:539a:b0:17c:2044:7bd9 with SMTP id z26-20020a056358539a00b0017c20447bd9mr11042691rwe.30.1709911424674;
        Fri, 08 Mar 2024 07:23:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709911424; cv=none;
        d=google.com; s=arc-20160816;
        b=Yz0c5G+Rcmr6oC0lc6TiAqPZUbzYNqiiNtDRmRQngZplQ3j9xctvolobJqwmW/e3IT
         LFEhtHdtbdDqhxe1Zxu//VS+pOZa1MJw0VX0qB+k8OVM0RzhvpHeqd24AxpXnMyh354B
         vCxm+JlXd9enyLmbLD17RjP7nuDIxrVYYyzqqK4SHecI/XH65zerehkpRXij6FFvJ+dI
         NcpH93PqeQquUpHW5cXQlaIbsNmHBpSCzR5hZOI2F0GajMi71Uy6buvnp7J0vZ8wz+qW
         Jdpq0GD7luW5++hdlHlEbN8vIXnVGQRsNha5vRrwGlFG4IPpPB8Ke2LCAN+KryxBbWyY
         TxkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bcBcmCbNUNK8QMRYlD0suSpFuYeDhzgpUC/IVV9/I8w=;
        fh=kFZEagRko8Kg2CzySF6/peapYp0hIfgeUcTBvYkvwkk=;
        b=ZhYSzyotUMq5ijKe0/rwLj3fNzBkdmsFa9sJCscgFs+5iZs3PxoztKrOLtIlgaTQ+P
         eSzSVQczVUrU9JBqDKzVj/6TPIuDMOSADWQOMxXWeeqcF/D76jynCVrqcI6euLHAdCen
         lr6yTvLPhg4Lu5YLVMc6A5/J1yFcAG7dd9rDZdmsbHxIXU4gZuZbfcXQhWeB4kPgyaZK
         bdJhT8QiYT8Ud326CWBMskeL50bGMTxjD+GM3l6F9OI1YhCPJwJ0Yf2au91CF7QobHgj
         ReBAawX+YJZj17oHuklq3PpXdG1qA4BouOSN/5NvfY1xxEajGxYQad3mQZkbBF1O2v+u
         Kb3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QM4oFDAc;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id m9-20020ac807c9000000b0042eec4134b7si895159qth.5.2024.03.08.07.23.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Mar 2024 07:23:44 -0800 (PST)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-29a2d0f69a6so1489616a91.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Mar 2024 07:23:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUE3ghyYbHPJ9mh6cNOxTiA1x213p/lCn6eQyZUCYRgCDfek37alB+/zW+CHIYvZY1le3pJhdWmeHj+861rDAjU89mmkSjaeUov7Q==
X-Received: by 2002:a17:90b:613:b0:29b:90d7:36dc with SMTP id
 gb19-20020a17090b061300b0029b90d736dcmr281082pjb.19.1709911423609; Fri, 08
 Mar 2024 07:23:43 -0800 (PST)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-25-surenb@google.com>
In-Reply-To: <20240306182440.2003814-25-surenb@google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 8 Mar 2024 16:23:30 +0100
Message-ID: <CANiq72mUJ6Nv+tDFoGbRYJs8Nzw18peFU3U-2cnz9MViyiG5ow@mail.gmail.com>
Subject: Re: [PATCH v5 24/37] rust: Add a rust helper for krealloc()
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QM4oFDAc;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 6, 2024 at 7:26=E2=80=AFPM Suren Baghdasaryan <surenb@google.co=
m> wrote:
>
> +void * __must_check rust_helper_krealloc(const void *objp, size_t new_si=
ze,
> +                                        gfp_t flags) __realloc_size(2)

The `__realloc_size(2)` should be placed earlier, i.e. this triggers:

rust/helpers.c:162:20: error: GCC does not allow '__alloc_size__'
attribute in this position on a function definition [-Wgcc-compat]

With that fixed:

Acked-by: Miguel Ojeda <ojeda@kernel.org>

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72mUJ6Nv%2BtDFoGbRYJs8Nzw18peFU3U-2cnz9MViyiG5ow%40mail.gmai=
l.com.
