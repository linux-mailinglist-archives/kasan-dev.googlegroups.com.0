Return-Path: <kasan-dev+bncBDRZHGH43YJRBDNR76CAMGQEHZIE5UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F22D38194F
	for <lists+kasan-dev@lfdr.de>; Sat, 15 May 2021 16:19:58 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 88-20020a9d06e10000b029030513a66c79sf1551954otx.0
        for <lists+kasan-dev@lfdr.de>; Sat, 15 May 2021 07:19:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621088397; cv=pass;
        d=google.com; s=arc-20160816;
        b=t4TuIBeVoGr1Pq8GcDiaJOkfeOi4gaZgzi3KdDnLWhgI7b3hsvwbShAfxMG2DZLR5Q
         XIIwtMMxt5awWhkM9YA8AxE+KkOc3ZjZ/Ei/ICBjsTZEf0nmURdDnLvtL+YNT0DDHSwd
         n6zVB2kJfh4Ga7KKjzZl29NzDr2P6k4x8NbsvmCLMyI3JGQEe98bvuPdtw0VpLTU8BHV
         lMbkeH4yl7UIMxf69sG/sBSSTHD1Fx99tfDUh56sTQcZGLPxPOT4DTBi999ukSI2idlj
         HXft4nMn7Yt6+cP0JNVs1EX1U6LP4yRaRuMqBAUMf3uVPe35ngVOFUILkj2jnj7EvIqU
         fZog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Gje0enMasKEQqG1ZTCv1F1xrUiuSRpWmc4Hu8xWwEEk=;
        b=IyN6ojp+FtZJlavIEmY0+8FwwWswTzTuf01gFucI0KpLbhSNWuDXJJ92iChhM6GAw4
         5yN8KAw7Vf0moTdH/31nMEFSm7pJyaDxtLDn3GnLBl+OM3TWatunCJj7RklnCfOBdjZP
         IP0EGLop7mmJSylfYjerWyF4Q/jy2yU7QWkLqYcGLIWmU/RZ1eLmVV940dAABlTorkhL
         RE4uzwA7jj3Slv/a7Oxus5gxpBH5e+cBqeWOKWk5ul/WSJuSre0VjGQotIJP7SrnWuNF
         XvxHAB2Ho9gwI5/vd+piJIq6dnA69ec0IAKg2zdzEKdKi7XbhwfR1KO62EwNDQaGsmSz
         ePvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BlIAn7yB;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gje0enMasKEQqG1ZTCv1F1xrUiuSRpWmc4Hu8xWwEEk=;
        b=NK1VbEVYVhoqUVeyae3vEky9Td1JR+iqOcEFBLlg3y78R4ReIPkGK8TR3fwJ3AncFx
         Q88350qRZw7FTWwiGOIq6bVgYJvqMV8o9yBBOtfethSUwYD7vrNSulcMX67+AsTwZsJU
         Bm2kvhZKtL92NQAkgT6p2HcjngTnc19UGIxPxJwD00V8vMkoVjgkzPMb2FjG9mLkeNY8
         NwtYsg5CkKaGOwvSc39ODm8er16fepSLCLz4begKhbIrXHtPCM072nSomztt65qsXiqr
         smqfg5AJvtYto3tPO4giRj3VuotnuJOeoYSpHznzNZp3J7eZjmz7pary1iGSR/Ht49F0
         BjTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gje0enMasKEQqG1ZTCv1F1xrUiuSRpWmc4Hu8xWwEEk=;
        b=feIlDfdTRPbl2dkYH/doKlIz5oJZQFByKTD7s+nW8zWYdqcaaoORwBa/uGzxmeMd6g
         Iw6s8iWhJbakc01tnlugiV8IJemDVHL2wOPwxS1i6p2NPykeQA2rFv5bcqxNUw3zCfku
         S4wWN1n1yc91utOwBrTao5G+BDZtK7lNtcNTn2fO7beqZLVp2WZW6djcsTbqhmf7ENK4
         2izgTzOvYVGm/gPfcXHmBBgXabsKJGkG6oIEcEo8RbqzhJSmzwQu7euhrrsWdK9l0z5e
         jR64gG3J0jxwnyJlBYMNr3dySlJOypWjw0ymvGFWhAAaGLoEJTagq636DKN5kqFbGaBn
         ieiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gje0enMasKEQqG1ZTCv1F1xrUiuSRpWmc4Hu8xWwEEk=;
        b=J47tMTVZ8etjwsqlhdMPkdD/ZbXUADMdb8xVRwzPs7itbbXA93BOY49PmzW2J6yBHq
         PA494sLrHzHn6789Pk7cjc4ojpHi3K/oro6PyTFUTfgZoTVdcjZ4zQAIpEIXs/1eDW9m
         dRuF0qTNxazJQVXQnWoCa5DN8v0uBaaPJjKmub92Ne7jDQMLFIfaT83R8ABrY3ip4ZQz
         vL8EbuMnKAuTo+oTfm+hLdgbKejs4q8awqPstbBPD1TC6BISLaYnh4E8daF1C1dAYgM5
         y4UkZnsK+RKCDcyyDB95GnKegVW1Xq+s2UAtzqDtoq80w6KzEHRTbkRzpIBqed3ypBf+
         zCJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JuBYM8lu+mkMcjfBjzUQab5kKScvjaRVADdaU3stKEJyrEE2F
	1a49eo3E9SrpxjPhwiHxxyM=
X-Google-Smtp-Source: ABdhPJxWzLrw0l+gt81lFY2uSjmjR/tl7oXZLZVkHaTe63bTy/GgS/VNSNgKFHAkGS2LMesddowLkQ==
X-Received: by 2002:a4a:e512:: with SMTP id r18mr39926173oot.40.1621088397218;
        Sat, 15 May 2021 07:19:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c4cb:: with SMTP id u194ls3131911oif.10.gmail; Sat, 15
 May 2021 07:19:56 -0700 (PDT)
X-Received: by 2002:aca:f2c1:: with SMTP id q184mr9780012oih.29.1621088396812;
        Sat, 15 May 2021 07:19:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621088396; cv=none;
        d=google.com; s=arc-20160816;
        b=mZm54xRTDeOvfJBhjYBuFk7JlP7GqFLzRngCOzB6WdtlI2E79+pJ8lrvux8/Xs0CG6
         zWg0L6jcq07LZGWQ0V4/J8OoXPcGT63oCsDzNky5IRVzxemYbIdHmJd5F3rGQK0kzhIR
         dU1tD6qiYY7h76mCjBRYOqDpa0T6BXfMA9VFlQeFliM1D/sCSGEIeQsAwqSHooKmhm6x
         7P8nM7HuTbDldUMKGWhRlYaLndrZzNAcAMwpCtSNhMnHUZfFlRyOZR6OvLo4OsrJp4il
         gAug4ka1eIuEOccEpxpPAcrTAL1QlblKnmKhEIg3bYCqtZNw+rlVY9AK9OeQTE+cmegQ
         avKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M7FG3BGvp3UM5jwkyXQ9ZlVnWzk7AoLwEg4DG0jV0g8=;
        b=I6yannrft9W91qO4slRdmkVM6YiPqze7MOi+RtuuL9RtM4JmBteTihFvn8K5CczgyU
         1AJxrHo5glNVGufXsE3OZ4RiT1+lzZlMr72nhTtdE2PLz3YBfl8d6okc6bGZMXTrlfL8
         4KBbBO2bS/2tmtedz97uosOkbLb8sfmhTIMhILgNWdqbE3kBndzhn6aBv21SUP6JH/jA
         PwyV6KBUp2qNTAOs91fRcn0MElZTnWzKyShO0FbJY3LQjUs7o5otcwOIBNceKuVzjwlC
         5nS7wm2ZM/okT1GLrFx1WjgVFRbELiTj4d1KyzurhJKKbgjeHZEWWsEl0MYyP+V8B8dX
         13TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BlIAn7yB;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id x16si957417otr.5.2021.05.15.07.19.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 15 May 2021 07:19:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id e190so2689750ybb.10;
        Sat, 15 May 2021 07:19:56 -0700 (PDT)
X-Received: by 2002:a25:8803:: with SMTP id c3mr36944040ybl.115.1621088396581;
 Sat, 15 May 2021 07:19:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210514140015.2944744-1-arnd@kernel.org> <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1> <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1> <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
 <YJ8BS9fs5qrtQIzg@elver.google.com>
In-Reply-To: <YJ8BS9fs5qrtQIzg@elver.google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sat, 15 May 2021 16:19:45 +0200
Message-ID: <CANiq72ms+RzVGE7WQ9YC+uWyhQVB9P64abxhOJ20cmcc84_w4A@mail.gmail.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=BlIAn7yB;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Sat, May 15, 2021 at 1:01 AM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
>
> FWIW, this prompted me to see if I can convince the compiler to complain
> in all configs. The below is what I came up with and will send once the
> fix here has landed. Need to check a few other config+arch combinations
> (allyesconfig with gcc on x86_64 is good).

+1 Works for LLVM=1 too (x86_64, small config).

Reviewed-by: Miguel Ojeda <ojeda@kernel.org>

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72ms%2BRzVGE7WQ9YC%2BuWyhQVB9P64abxhOJ20cmcc84_w4A%40mail.gmail.com.
