Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBNVLYL2AKGQEUGSCVQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 935781A47F9
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 17:50:15 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id x25sf2050848pfq.18
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 08:50:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586533814; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThOi9WS0biDT4tAhc6kCAuXAjStwKRzhS+xjrEDIIhYxkIB7gAgtRs1W3b8yRTmlDz
         ajQZOe3YneUjz7ftTt7dzUa3mUBYGVlCxwYTCXBZBI2Owu6WqLWvOmhRanzlZhMv4Lql
         7XwcQAW/RuMKYMAy6n+lF13JWV6yE2p9MxUMUiC8Wdy1cywYYPLavyMWV6kxpuG5798R
         is4OjZ+lzPesu2rrWtgV14TtsconFprft3NzeNdPnBJGNcYXLLPaQpK+OEQyXLFOkKBl
         t0Euu5vAJiqibHy5hyNUIzQTEbFFQyu3apEylC+7pFP9LFqP78S2JcXD7O8v6sVvUMB4
         HjqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=utx1/xtZRsUcDSF/Ikez08e+PUKlKWe8UaJ+KVPN2oE=;
        b=dfIMydUsSXJ/+Mu2wvXTNKnEw2DHiEtdQHVrFt1VFZ4cEMSyGU2//GngCDuWk4fGP5
         iop7qxCX+cJL+zR9ULwYBVuS3fIgsW3Aq3WZJxjn+JrVtrF3JbUs2+MLfd/kfGvZpyYE
         EcUoJHGwXuW0wcYLkDEUVYlF5Vk1BFEVyKkpslE9RsAPhs1w8QK8eXmxhHMENuxTmnI0
         MYlbMGvkC4MfEHgHAW8JN1JUiTrOl2h7Q9ENp11T22mn80qCNuDm5Ls5/AngM18+42se
         m2fK6GpTFNEzKgtb1ZuCPua9oy0isUDuo5OK/YcVDaJvsAm5RzOebPtNsIvuLqoJq4R3
         mv/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=K2kWQODX;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=utx1/xtZRsUcDSF/Ikez08e+PUKlKWe8UaJ+KVPN2oE=;
        b=IYIXEJdVw4gFx/SjW3BPDPqQJB7978tXTLWUj5THW+zGA7PjWCIfAvmLixDeXW+PFH
         7cz0YrU8zxVxRTEhyhbZmH9vOCEnkY1iV6I1TEVekMU1VyFFN+h3Zf0wW99Z8mgBi3up
         vH82KoaS2oeBLYAaebqrfFo4XylU5odnFiB7CfLUF8e2OzEKxiFFxCH1V21K3KUage8d
         5TIQ8G38LWj6yqRcusNQM9uEhY+tCpf/FoZ8APiHuuptuRgxPjCy7GoralTf2tGv5DxI
         2B7LNZOJohtN69KulpQyM3/janXcXG2TWAF+tIx7BZQvwrzL/XizP2l0PrTRFXHXskcF
         6ovw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=utx1/xtZRsUcDSF/Ikez08e+PUKlKWe8UaJ+KVPN2oE=;
        b=uPYTfPHmljLNm5hK4XfQ9u2XjjCKFfM5MJpZjbugmCcwMyU/jrbJAQSB/2362HNL9L
         Mr/lHncKLHq2QDoDfU+dJmft++ay8z/iVZxI1Kg38XbXZNhCucd68YFYISNqVcQAhNcJ
         FoPw9Gt3uzcnzdQdgg/6yj3qjzsumro2VuaRlwPhhVsQ/cqFezXq716dyuojLhZVnhMR
         Jwj495iHiWei7BKGQLicmjjSXUX63mQAUI/5gUni9PGFsyAp1+kzuQ4ds94QcP/Eentj
         0/JbEYYd64ooYk1cU52NZIsYRJLHMn/cxF/9vh1Bn5VE3fnu+7HihbsJhYta2D2WOqVn
         C/RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZiSAnC7uFtlLK1B8Kk/f3ThE7psAV7KL0L/R22Rp401yasMjWH
	0uGR5w2kGlHnPtbLerUwPfI=
X-Google-Smtp-Source: APiQypJbdkLyZBhkAFnJWsEMryWIBSjc4i+iJjH4kePdMStdoXZkLoguufb7iMQlVnMTqtAF80tzZQ==
X-Received: by 2002:a17:902:a5cc:: with SMTP id t12mr2578529plq.147.1586533814105;
        Fri, 10 Apr 2020 08:50:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b58d:: with SMTP id a13ls5431763pls.0.gmail; Fri, 10
 Apr 2020 08:50:13 -0700 (PDT)
X-Received: by 2002:a17:90a:34e:: with SMTP id 14mr6315816pjf.32.1586533813634;
        Fri, 10 Apr 2020 08:50:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586533813; cv=none;
        d=google.com; s=arc-20160816;
        b=SIglWLx6C6b7J7mk5CKLsU+xJm2HEOlted1NngDL9Y/LLovon/n44920i18nbuoNMu
         nSZ6Jqb0+Hi3sBsT9TVbFVLkijikgGV51AQBkNO56LIMLhtA/FWr8OsDVrmGGzK+Aik0
         mI4ANVPa8z7OQxRV6zQIs2RU25Kgt3ccjyeNZm1GytpiGfRJygcnzbmeVgI78vQh6lHA
         2OlRg1TVXcP8nvKCEEs9reO+VVRcNAU2v66/LlVQg5SVhImBkpuxK9qv2aLbtrGn7QH5
         7WHjkZEg75bxeOp400kpHmpYgjWg36dvcWMLiyzbeP9xhl3PJnM4q1ySxYN8RPdt6pXn
         viIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=ngAyglUW6GXylRlLf8NoeOB2cXhi0dD+XxTxvWca+JA=;
        b=B60AmG6VG4i0kAt6o89aphAUhCLXQGsrAwO5b46pNa1rxugdV9X7UvtKCmCQl76NHq
         h+XMJPlDtt/Qr0/zHdZxXL8bjppziLKW7rPjAoleF55nrfMhXC+mYHtMku9TaaArM2Km
         lJhGmchqpk5Y7hWtZo3B8uugP/6Pw2PpXaoghG2IWRo533knC7iEw4NWBeS6Z4kI5Glk
         E6Vv9u2zI1FzkQ9/CBBM1qFXdRvEOzmYBTDDMEzUV3WDb93eMfhAhhFQYbqLQa7Dc+ew
         5Mm08vi9gioZmKW0oC04lqfQSrd2MwoiKDmN3jZFbCm0BxsafxoPhNNFCuiKTnpE06lY
         kHJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=K2kWQODX;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id g23si200729pgi.5.2020.04.10.08.50.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 08:50:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id x66so2507170qkd.9
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 08:50:13 -0700 (PDT)
X-Received: by 2002:a37:9c4f:: with SMTP id f76mr4535161qke.294.1586533812612;
        Fri, 10 Apr 2020 08:50:12 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 206sm1897059qkn.36.2020.04.10.08.50.11
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 08:50:11 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
Date: Fri, 10 Apr 2020 11:50:10 -0400
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <B798749E-F2F0-4A14-AFE3-F386AB632AEB@lca.pw>
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
 <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
 <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=K2kWQODX;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 10, 2020, at 7:35 AM, Marco Elver <elver@google.com> wrote:
>=20
> On Fri, 10 Apr 2020 at 13:25, Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Apr 10, 2020, at 5:47 AM, Marco Elver <elver@google.com> wrote:
>>>=20
>>> That would contradict what you said about it working if KCSAN is
>>> "off". What kernel are you attempting to use in the VM?
>=20
> Ah, sorry this was a typo,
>  s/working if KCSAN/not working if KCSAN/
>=20
>> Well, I said set KCSAN debugfs to =E2=80=9Coff=E2=80=9D did not help, i.=
e., it will reset the host running kvm.sh. It is the vanilla ubuntu 18.04 k=
ernel in VM.
>>=20
>> github.com/cailca/linux-mm/blob/master/kvm.sh
>=20
> So, if you say that CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn works, that
> contradicts it not working when KCSAN is "off". Because if KCSAN is
> off, it never sets up any watchpoints, and whether or not
> KCSAN_INTERRUPT_WATCHER is selected or not shouldn't matter. Does that
> make more sense?
>=20
> But from what you say, it's not the type of kernel run in VM. I just
> thought there may be some strange interaction if you also run a KCSAN
> kernel inside the VM.
>=20
> Since I have no way to help debug right now, if you say that
> "KCSAN_SANITIZE_svm.o :=3D n" works, I'd suggest that you just send a
> patch for that. If you think that's not adequate, it may be possible
> to try and find the offending function(s) in that file and add
> __no_kcsan to the  function(s) that cause problems.

This works,

--- a/arch/x86/kvm/svm/svm.c
+++ b/arch/x86/kvm/svm/svm.c
@@ -3278,7 +3278,7 @@ static void svm_cancel_injection(struct kvm_vcpu *vcp=
u)
=20
 bool __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);
=20
-static void svm_vcpu_run(struct kvm_vcpu *vcpu)
+static __no_kcsan void svm_vcpu_run(struct kvm_vcpu *vcpu)
 {
        struct vcpu_svm *svm =3D to_svm(vcpu);

Does anyone has any idea why svm_vcpu_run() would be a problem for KCSAN_IN=
TERRUPT_WATCHER=3Dy?

I can only see there are a bunch of assembly code in __svm_vcpu_run() that =
might be related?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/B798749E-F2F0-4A14-AFE3-F386AB632AEB%40lca.pw.
