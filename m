Return-Path: <kasan-dev+bncBDI7FD5TRANRB3VBSO3AMGQEDFEARJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D107958D22
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 19:22:56 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3718a4d3a82sf3267747f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 10:22:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724174576; cv=pass;
        d=google.com; s=arc-20160816;
        b=OT3qAatpTgnh4crdqUw1Ji/g7z2NHBnIM/4ZPehfJ/izbogxv1kvOzLmZJbKWBnt5G
         fScbMyPU6IQqgDyPHDDSgLLKjfMQPwwbNMWNaVgtVRDaJoOZiheMEIvEgkxmpM+Q+dkV
         NkKJRsV+vYB+5OAzjbDJHRCI1AO6Z6xDuRZdL1rSFu8X9Ebkd3XrxIXAJJHvUonGz5n9
         rh0o1toz7zDYOGDBwnnexw78uzuKSyLDPQ0RCRjyEx5vmYk7FP0TTLXU4u1MsM/+3l3S
         m6buitF0ArFAe+w/BCGKA4GQtDnZLVd8N3xTvg+ciWmNaDMNVqO+x/jNNU+P9k/HRwsU
         MSGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZbH0B3MV3ZeGgr7sc+OoI9JGohoVRImr8HBJJLZBeVU=;
        fh=kEYwPbsUKF9JJeLTmUJrqSvknrlOhFuGRRJZj2Sa6BA=;
        b=JmCydDVwSmH/qIxJ900inYhIBxemK0Ty+ESBno9RCU7/Nr3nin4dICfNbqspe4a7CX
         SlPq8n4gZd7Dwe66oD/qgYZgtRn6sllRuQlQjNKXadSCypOTZoEjWi+KZdQ1156pDH79
         Fb2fG/h8jBUolURJM6cXzrHb06kny2P9Bd+Wvw8VVcm+QALrvl2Ly5f+Qp7vU6VbPY4z
         VXS3hFai8mFzT6Imwfr+cRj1nlImhWKGbQxGNvmsr1FIaGitWwb7lCjTXnlftnva0MBn
         N1apC9KJYeOwtvqNqyxBxituirdN3W1sEfXVrEkDwLzqOt5ZEL2OdyogJ3zfccjS0S1M
         hKeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="WKsVo/84";
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724174576; x=1724779376; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZbH0B3MV3ZeGgr7sc+OoI9JGohoVRImr8HBJJLZBeVU=;
        b=OHm+VBMQIr5w4UtuVeTpzEsMIEU1Y+n8BKVxxmr4bwiWGh0Enb8P8ZSHeYtMmjUg7K
         RrkVwlEF7qMcyaAaNLs89riQnnk+DFacvb6o/ru7ZJCnFIWAuKfL9szV+qP2gFs4szsq
         56v/31BQGLuBBBQurYKsm6rrzEUhYHlGcN6eByDiBYv3xzIXRZZMua8z2sUq70qcWISx
         zvrm485/ap2aYsYc6vuRKGiJ2s7hDkCEAqAVRK2B8ge7w66u31LPw3bnJjJwDrl8pJg4
         KYbnaHes2ZL1ADh2W4otMptK5N+uuVvIqG80c6Th18fVuucvxSdbYkXIaOyMlv47xWlC
         Pdtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724174576; x=1724779376;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZbH0B3MV3ZeGgr7sc+OoI9JGohoVRImr8HBJJLZBeVU=;
        b=hWBdkDWUmspapFzgCrhyrMM+qMPf4aW5CvDKf5G8s+aGiNgNv8AF4b7RIerLyMdnLr
         PDnnwj6qEBPQn6ZsbNvoL2WM400tmX55ItNML/tVcJvoIuP0xqpjaEO80REf345vD+qG
         pqT0e1qHRvJ5ojTWgSUuFabVVXFjSYf7r9xa56b1k+0ziAEYgXgUlII+sALKtFa/sAz2
         AW4U+o9+Evae/dioVjeqwsAIPyhfWFf8pvnNOatEngyolzSJfQTZfbeHamXd2QgviF8V
         Tg5zbE770wDrvBoBPhIVgSVxSdoS+6GowxzC0/J+DBTMXkZNQHGiSOU8i2e2P3jqfmUV
         t/qg==
X-Forwarded-Encrypted: i=2; AJvYcCUmBz0dh5kj0SGDYs+/vtnN9WHZIu+IIlwhx9MF21TpKdvJ6GALOSppy6SADU9pGzQXo5s+nOyBW/Za9kd3UQEzafZSeZmMNQ==
X-Gm-Message-State: AOJu0YwxXb05CZILpSGFyE8dVPfP1X5Ye/rsBL+2owR5L6ZkF+RE5S8k
	LBVjjqF5BQDHVL8bX+sOEWOEFWNN/kQ3NNZcGAPLTHI/vUvFJuZ4
X-Google-Smtp-Source: AGHT+IHKLBenF3HwDLGz/c5RiQ5bPvOeYirqMuBVmrfB/GzvlV+Vr+OfpkK+8Imq1oIXG/2mWMvWqA==
X-Received: by 2002:a5d:4e4e:0:b0:368:327c:372b with SMTP id ffacd0b85a97d-3719444bfa6mr9849188f8f.19.1724174575136;
        Tue, 20 Aug 2024 10:22:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5392:0:b0:368:7a83:35a4 with SMTP id ffacd0b85a97d-371868f3b09ls1600986f8f.0.-pod-prod-06-eu;
 Tue, 20 Aug 2024 10:22:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUl2TL7G7CNGaJr4WtxIRyfMDoRRImeqWDdJ/UcZKcIyVEeUx9GWAKeb7oyk/l/KoWygjIHEC5x1ixq5VVp10snTuItRfuNv8bTVw==
X-Received: by 2002:adf:b307:0:b0:368:4edc:611e with SMTP id ffacd0b85a97d-37194344041mr9664589f8f.14.1724174573066;
        Tue, 20 Aug 2024 10:22:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724174573; cv=none;
        d=google.com; s=arc-20160816;
        b=dcmhMPGYbzQS86MHP2NHcMQgFtkpcEXmX+4vNQo+faHHVxmwk2oV4P0W0jKKUqTXd7
         s4Rvj2iB1oa4g6hJpbYeKMc14TGcQFX0hlbT36ngl4LQLylK0fUioZx4wsibJ90dTC9s
         LE4Bi3LVFyy3Uj7FTBxDQVFSWTc+aXr6o5hi8BwCL1Og8mKFWaFRRi6Lrtfa1iIh+EiU
         mhdxufJ1Viqmdlvpl1RR+OYOBCUpaCkVSXrjVAXi3Av0UoTLCNBnXeBYGEezHVdY+TdW
         6TWuqOlqJk6HXpTla4TVCnrFbWVtCoSk6ovP01ZzdoMGqzeqfUWpKHxQF2tpx+yAWxkY
         lNSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T/1WG/9ldCtAUxEKSi+2OpNUvCL9Q6L1YzxrQLiosWY=;
        fh=BWZF7huiRTeYvVXm36m2wttZ/bM9HrvHO/uU5GH4sjo=;
        b=pJu0K5xtdpEEPJtp+iyXFM+fbesr9r6Aq/wtbMGu/8mmz5PP0gHkzYrWY0N5zQLkzC
         w0qL4gz049cvbcc/eeYc02uSly61Ba0fCDPJHYydrGSc9cSA0Cd0F98acJNddnJoJMwy
         9djVVxWr1qJlqk02G15+AS2Q6CPGqWIYZqEqG5tVY2P8xSwtQdZ9umeGQzPJZUPoKwWz
         FR6cdoQN+Xu8lvA59QumugCWRM6fLww8xBQLMDHRVq8YTXXmsctAW/uL5A0FHZcmzUfb
         Pi73iSjzCdIs5OcjrJOAlV3H0w5V5VTrLBWM4fr4PuvpzCqwhlFaX2DxEpCWFkrWrUqU
         r9xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="WKsVo/84";
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-371898e9899si249995f8f.5.2024.08.20.10.22.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 10:22:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-5bebb241fddso606a12.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 10:22:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUzTrtNmcSeXJPGLR5ZrgSLZofzrQlngwNIyfeY+Ir2e8HxFcVmRyVtmdSMG5anlwg0bDMASjHlYuY=@googlegroups.com
X-Received: by 2002:a05:6402:35c4:b0:5be:9bb0:1189 with SMTP id
 4fb4d7f45d1cf-5bf0be0c727mr163175a12.2.1724174572142; Tue, 20 Aug 2024
 10:22:52 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <20240819213534.4080408-2-mmaurer@google.com>
 <CANiq72k8UVa5py5Cg=1+NuVjV6DRqvN7Y-TNRkkzohAA=AdxmA@mail.gmail.com>
In-Reply-To: <CANiq72k8UVa5py5Cg=1+NuVjV6DRqvN7Y-TNRkkzohAA=AdxmA@mail.gmail.com>
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Aug 2024 10:22:39 -0700
Message-ID: <CAGSQo03GVik5_yXFmCUnNUnPUwuwk-YFA0kqBd640PUjFOXcGA@mail.gmail.com>
Subject: Re: [PATCH v3 1/4] kbuild: rust: Define probing macros for rustc
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Masahiro Yamada <masahiroy@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>, aliceryhl@google.com, 
	samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, ryabinin.a.a@gmail.com, Nicolas Schier <nicolas@fjasle.eu>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="WKsVo/84";       spf=pass
 (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536
 as permitted sender) smtp.mailfrom=mmaurer@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

On Tue, Aug 20, 2024 at 7:20=E2=80=AFAM Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:

>
> I had some feedback on v2 -- was it missed?
>
>     https://lore.kernel.org/rust-for-linux/CANiq72khUrha-a+59KYZgc63w-3P9=
=3DDp_fs=3D+sgmV_A17q+PTA@mail.gmail.com/

Sorry, I did miss that in the refresh. To respond to a few points
before I send up a replacement for this patch:

>>
>> 1. `rustc` support will soon be a minimum rather than a pinned version.
> In the meantime, this happened, so we should update this sentence.

Will update.

>> 2. We already support multiple LLVMs linked into `rustc`, and these are
> I guess you mean `rustc` is able to use multiple major versions of
> LLVM -- or what do you mean by "multiple LLVMs linked"?

I meant that the `rustc` consumed by the kernel build may use a wide
range of different LLVMs, including unreleased ones. This means that
which options are valid fundamentally needs to be probed - there's not
necessarily a clean "LLVM version" for us to use. I'll rephrase.

>> +# $(rustc-option,<flag>)
>> +# Return y if the Rust compiler supports <flag>, n otherwise
>> +# Calls to this should be guarded so that they are not evaluated if
>> +# CONFIG_HAVE_RUST is not set.

>Hmm... why `HAVE_RUST`? Should that be `RUST_IS_AVAILABLE`? Or what is
t>he intention? Perhaps a comment would help here -- e.g. something
>like the comment I used in the original approach [1]. Otherwise we
>will forget... :)

Yes, this should be RUST_IS_AVAILABLE, will update.

>Also, I guess you wanted to relax the precondition as much as
>possible, which is great, just to double check, do we expect a case
>outside `RUST=3Dy`?

I expect this to be potentially used for whether you're *allowed* to
set `RUST=3Dy` - for example, if a particular sanitizer is enabled, you
may need to probe whether Rust+LLVM supports that sanitizer before
allowing RUST to be set to y.

>> rustc-option =3D $(success,trap "rm -rf .tmp_$$" EXIT; mkdir .tmp_$$; $(=
RUSTC) $(1) --crate-type=3Drlib /dev/null -o .tmp_$$/tmp.rlib)

>I also had `out-dir` [1] since, if I remember correctly, `rustc` may
>create temporary files in a potentially read-only location even in
>this case.

OK, I will add that.

>> Also, should we do `-Dwarnings` here?

I don't think so - I can't think of a case where we'd want to error on
a warning from an empty crate (though that may be a failure of
imagination.) Do you have an example of a warning we might trip that
we'd want to make the build reject an option's availability?

>
> Thanks!
>
> Cheers,
> Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAGSQo03GVik5_yXFmCUnNUnPUwuwk-YFA0kqBd640PUjFOXcGA%40mail.gmail.=
com.
