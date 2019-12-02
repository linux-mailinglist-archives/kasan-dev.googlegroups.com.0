Return-Path: <kasan-dev+bncBAABBEFYSLXQKGQEVJF24SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 34CD310E532
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Dec 2019 06:07:30 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id l2sf17859506qti.19
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Dec 2019 21:07:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575263249; cv=pass;
        d=google.com; s=arc-20160816;
        b=im5yEf8NkDjc9rVEFSWjeQWv+MSunbwMjeMiejjlBYyCwsqI0Zig87NZ3TXrnnlZbW
         gQhlKtAubRE3DqSNFugKburfqeDNWVpgPGq7R0PxhGIXveUpMHq0YzOAF8kw70MrXago
         Nffh1bAyZ9uGgwEChO49ujzHqa68E4dyS8dsGG8CCuG7ptGLqxQeOV6Ca3EtUidWc+Fb
         Xz2NwZSj6DG0qP7e6isfVI90O3jZ2qs3RDWE07U+BE8c5L6FEHH54IyWHyAto9SfFr+d
         MwPEVhsNrwkndBxZ2KPfUk7hT7KWNvfCd5ayhKQKrfUnqE33xk3dqjIVqiflYbMCLWrN
         /aOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:content-language
         :thread-index:content-transfer-encoding:mime-version:message-id:date
         :subject:in-reply-to:references:cc:to:from:dmarc-filter:sender
         :dkim-signature;
        bh=oBdIldbKnghAKLklykkgnGHEK36ETzowC2vsQHhX6Sw=;
        b=pv3MN+BhucB9kSNPhQqSfUXBMjCwKqVToX2OxP72EegzWdQv83p7lrwlJvPi7KAr6f
         8wo5eotrem8nEe8VmPNT0swF7tInR/JbcgSQ5rJH6UT22WQMFNtqA7fdIkO2WOvnVH3X
         bxmXWYxSufFS1dpjyk/1/UJ23u/jjaCduZcjIYpR1XgIcdu8lV6hs8Ts+VUPGFsSTSzx
         qzePBcrsidp89QLad387gS0xN9a+eJHLbtCSseL3nH1Arwsg4ZxQy7h2JlZUPbyah4aj
         C3o5USvx9KBgpQA+MD7jIE8oe0ufUmd+3S50apScH4a90AnAOCKDhVCzwFvnmf0DwOnA
         RCIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codeaurora.org header.s=zsmsymrwgfyinv5wlfyidntwsjeeldzt header.b=MXWqW4Bv;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=CJqWSndz;
       spf=pass (google.com: domain of 0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com designates 54.240.27.187 as permitted sender) smtp.mailfrom=0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dmarc-filter:from:to:cc:references:in-reply-to:subject:date
         :message-id:mime-version:content-transfer-encoding:thread-index
         :content-language:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oBdIldbKnghAKLklykkgnGHEK36ETzowC2vsQHhX6Sw=;
        b=PYIZcgd/aRdnXaSslptoWNXX2pwgNEqT/kvmL8PoNwKA6SSGv44ra+d3IpS5FbRGuz
         aor04jF1y5EtRI01N6s+2RuZ/4E+z0xL4HD7CfFa3vMBH/mSoc5BJczm4Rp3fdvsVpa9
         zpB/GuuxI4qhsWplCcP49ftZN9aLaee2c5ZLXsVm7esaSFPi2mWNOqTDEhdqbD6wSE14
         L0ZlrDm5lWFhCA4VdDHt0p1QST7h1LDrNP/9yXyVc5v1snzHfaoPqTWJR97OEzotJnMz
         FmW6QzqaU290r1Bi6gjNC6g+7R/fiubP13k3ZVM2gzgx9ly6/bWt2PwnWiUg4NK/KHx7
         vHaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dmarc-filter:from:to:cc:references
         :in-reply-to:subject:date:message-id:mime-version
         :content-transfer-encoding:thread-index:content-language:feedback-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oBdIldbKnghAKLklykkgnGHEK36ETzowC2vsQHhX6Sw=;
        b=lnVQnSP4oEmReLYBK/bbLVdvQVkFZ8dhI64pM+adHBsTCX9NDj4UleY66CRxdvAr1E
         Z9f9QSdieMdk+9281+OG3L/fFIlCMj0/KjbHbh42O/PEymZ6Yf7ULMraPLvNdLazT+i8
         kkpTKsdQmTokh0PlMngHa3yn2nBIMgm52K9AZuHh5LmyLNjj9W4bWSowxmhQbIGZodXH
         aGTlmYDbdNRrh0WXsuQ0s3WTihAOBjZKOs/hFDILXfT6Vnbv8wfmAw4OOyyx7/xc4jgq
         gVBkS2QPTM9+ElyApb81mRqZCboP36znk8UYDRBNWGdwrPT1euGFcfl+dwOTrn6xKF+q
         KY1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQFLccrMKC6m8B2ClQb+Gxh/IConBQCHioyVdUkE/7MlCCWQpf
	9InwgNiqptlJjnfCUOZNhBs=
X-Google-Smtp-Source: APXvYqxkUfbmQB5MallizTSIdv1OxLUlEbKAI5KwAVPjoEsjVfR0jILEKiDXlBekO+3C2sPwKShRqA==
X-Received: by 2002:ad4:4c4e:: with SMTP id cs14mr30859312qvb.198.1575263248883;
        Sun, 01 Dec 2019 21:07:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aeef:: with SMTP id n47ls1166463qvd.15.gmail; Sun, 01
 Dec 2019 21:07:28 -0800 (PST)
X-Received: by 2002:a0c:f350:: with SMTP id e16mr31517311qvm.104.1575263248558;
        Sun, 01 Dec 2019 21:07:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575263248; cv=none;
        d=google.com; s=arc-20160816;
        b=W0pXc1JvpNnLfdBhU7C/18HfA6Hg7bYiT4r0RAZrHgSsUs5Kv0CXofAE84KWkjGo/G
         9Ce94IigxPfl7224l0AZmmmQHQuWnm/Y1+SPgFNamQNWyR5h1yudFqhFWzRDGAvFSV8d
         pkxwWV26lom0cQhp8j6G0ZewqEojKsspH8aRDNzy+MOAYRou9l/JuOkgLKb+XsFQfBk4
         VAcpOTdORGkjM0Dg7XnYsJswmmlqoCZ8zqoCZhC1DYutsQJraYd1SRgx5Gjm4wYtgR9o
         zn6Fl1uJdecngqAzgub5MXqWGBh1fqFRrQm4qSsQ3PMzrHeUOCcOcr4Ekw/CKm5kJxNL
         F06A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-language:thread-index:content-transfer-encoding
         :mime-version:message-id:date:subject:in-reply-to:references:cc:to
         :from:dmarc-filter:dkim-signature:dkim-signature;
        bh=rMxOBw3aWlogGDBT6R+kAoQRRttCZ1c1uAUUr62RFII=;
        b=E0eavhXDuSu0gYBmoPz9bfMJpw75VZmN+hoU/DwVvVfc1kKyidRQt1AtB06VscoK+7
         fIRji873wiLfwiR5JNPqiqxjEhRjQp0tQrb0tLDz/oUG/2SWQFn/8/55oYiswvOx8Kt0
         L3udBx3vysmGB/X3eTdMzD+bW3eTsdUZKiIe25o8GqZ7VQi1QBDlYFDpKUTYIhs8cNEt
         8wVC3qdlLIsd8kimW4kJnnkn3IJtlrKnm+9NnNJyuLm7FU9XeiWT8w41lcvBVou0hkNN
         hFD9hQFT2xxaxSmD89lZ79KvkieK4vj85aiI2X3QUeLMTm/HWuLfQ4ZOQv1yPHW7HY51
         RgQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codeaurora.org header.s=zsmsymrwgfyinv5wlfyidntwsjeeldzt header.b=MXWqW4Bv;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=CJqWSndz;
       spf=pass (google.com: domain of 0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com designates 54.240.27.187 as permitted sender) smtp.mailfrom=0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com
Received: from a27-187.smtp-out.us-west-2.amazonses.com (a27-187.smtp-out.us-west-2.amazonses.com. [54.240.27.187])
        by gmr-mx.google.com with ESMTPS id n22si149052qkg.2.2019.12.01.21.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Sun, 01 Dec 2019 21:07:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com designates 54.240.27.187 as permitted sender) client-ip=54.240.27.187;
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.0 required=2.0 tests=ALL_TRUSTED,SPF_NONE,
	URIBL_BLOCKED autolearn=unavailable autolearn_force=no version=3.4.0
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org E8C0FC433CB
From: <sgrover@codeaurora.org>
To: "'Mark Rutland'" <mark.rutland@arm.com>,
	"'Marco Elver'" <elver@google.com>
Cc: "'Dmitry Vyukov'" <dvyukov@google.com>,
	"'kasan-dev'" <kasan-dev@googlegroups.com>,
	"'LKML'" <linux-kernel@vger.kernel.org>,
	"'Paul E. McKenney'" <paulmck@linux.ibm.com>,
	"'Will Deacon'" <willdeacon@google.com>,
	"'Andrea Parri'" <parri.andrea@gmail.com>,
	"'Alan Stern'" <stern@rowland.harvard.edu>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org> <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com> <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com> <20191014101938.GB41626@lakrids.cambridge.arm.com>
In-Reply-To: <20191014101938.GB41626@lakrids.cambridge.arm.com>
Subject: RE: KCSAN Support on ARM64 Kernel
Date: Mon, 2 Dec 2019 05:07:27 +0000
Message-ID: <0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Mailer: Microsoft Outlook 16.0
Thread-Index: AQIkPOdSLH2Qcxx8ygFmLWl3/QxVtgJ871EyAngelYcCVg8vwqbOydmw
Content-Language: en-us
X-SES-Outgoing: 2019.12.02-54.240.27.187
Feedback-ID: 1.us-west-2.CZuq2qbDmUIuT3qdvXlRHZZCpfZqZ4GtG9v3VKgRyF0=:AmazonSES
X-Original-Sender: sgrover@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codeaurora.org header.s=zsmsymrwgfyinv5wlfyidntwsjeeldzt
 header.b=MXWqW4Bv;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=CJqWSndz;       spf=pass
 (google.com: domain of 0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com
 designates 54.240.27.187 as permitted sender) smtp.mailfrom=0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000@us-west-2.amazonses.com
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

Hi All,

Is there any update in Arm64 support of KCSAN.

Regards,
Sachin Grover

-----Original Message-----
From: Mark Rutland <mark.rutland@arm.com>=20
Sent: Monday, 14 October, 2019 3:50 PM
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>; sgrover@codeaurora.org; kasan-dev <=
kasan-dev@googlegroups.com>; LKML <linux-kernel@vger.kernel.org>; Paul E. M=
cKenney <paulmck@linux.ibm.com>; Will Deacon <willdeacon@google.com>; Andre=
a Parri <parri.andrea@gmail.com>; Alan Stern <stern@rowland.harvard.edu>
Subject: Re: KCSAN Support on ARM64 Kernel

On Mon, Oct 14, 2019 at 11:09:40AM +0200, Marco Elver wrote:
> On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
> > >
> > > Hi Dmitry,
> > >
> > > I am from Qualcomm Linux Security Team, just going through KCSAN=20
> > > and found that there was a thread for arm64 support=20
> > > (https://lkml.org/lkml/2019/9/20/804).
> > >
> > > Can you please tell me if KCSAN is supported on ARM64 now? Can I=20
> > > just rebase the KCSAN branch on top of our let=E2=80=99s say android=
=20
> > > mainline kernel, enable the config and run syzkaller on that for=20
> > > finding race conditions?
> > >
> > > It would be very helpful if you reply, we want to setup this for=20
> > > finding issues on our proprietary modules that are not part of=20
> > > kernel mainline.
> > >
> > > Regards,
> > >
> > > Sachin Grover
> >
> > +more people re KCSAN on ARM64
>=20
> KCSAN does not yet have ARM64 support. Once it's upstream, I would=20
> expect that Mark's patches (from repo linked in LKML thread) will just=20
> cleanly apply to enable ARM64 support.

Once the core kcsan bits are ready, I'll rebase the arm64 patch atop.
I'm expecting some things to change as part of review, so it'd be great to =
see that posted ASAP.

For arm64 I'm not expecting major changes (other than those necessary to ha=
ndle the arm64 atomic rework that went in to v5.4-rc1)

FWIW, I was able to run Syzkaller atop of my arm64/kcsan branch, but it's v=
ery noisy as it has none of the core fixes.

Thanks,
Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0101016ec5019b36-3a4accf3-30b5-43df-b3b0-d6fa38541f05-000000%40us=
-west-2.amazonses.com.
