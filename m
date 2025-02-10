Return-Path: <kasan-dev+bncBD3JNNMDTMEBBU4WVG6QMGQE35HHPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 820D4A2F7F3
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 19:54:13 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-726603f9478sf4049285a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 10:54:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739213652; cv=pass;
        d=google.com; s=arc-20240605;
        b=B6VxkxBJ8F/wzhqHrx9TtQrt9T5ThAxU6UljoyHglJpfYZGBzeQdzD9WbwJz3L3x8F
         KG0BmiMNYZwpHheZf0hUVbKJFNWWTNw43sm53JoBnqdrQtnLH3K20TviCmazqVlGmVdz
         gXzZIP3OsPb8/HciU85SLhbqBYZbbntKP7Ow7xs4SPfHYgkFhhMP9Eubjm/BUy64uByg
         NvOPCAwRLMG58fRVp1vEC7GTEMeR9mUEJKRZ/dNQUED5mEwakMgksQJl3ANTzg1YLtO+
         w5CxFWzhleHpdb0/vQ7klcmiJzrKv4kQ8BMVJ5GSG2ENhnDBut+qyVAX5yFbOaX4UyhW
         L21A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=FElwkrT2vJlARiPS4S9A1qo01ZL21h0LeVZcW8aCY98=;
        fh=nid6FDmjpk3Wl2hv5oiWKMpdZpQOSLn0cwAqnUs/nU8=;
        b=FDHXz6TwCCPl+YLXUnCkEtj9xBtV1MlwFpJer6bdJO0j+7tmEnzY76SLq2IRlKqPWn
         k5AbCTwxxDnqMay1zqr3hrr+aV9JGngfVBy0wRgqcf5rU5P3kgucD6bCivAv3Etwn8WK
         YD1B5kKhXFvDBNbmubcVAuMfCG3oPFa1KPZgveMNhP4EZX0WOk+BB2YjURPciKTINQsF
         5VdHu0iQW51Ib5OHYoA0TlAwBpuGa1Xexp/+xQ9UArErE50P7YGiwt0zdcw0Ctpho1MR
         xODPaGQlTcINcj4hMe7tEvxbtnmo36RLVsunf3HweQpD6HKSAb+NvjnLRQTlmGBDtR4x
         +DTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=3K5ArPU6;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739213652; x=1739818452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FElwkrT2vJlARiPS4S9A1qo01ZL21h0LeVZcW8aCY98=;
        b=r7uTEnkgdq6fHIqO77BdZn9bnr3woGtpj2Q/rEPI2ZxqUDEOjtCQ52KlSpNnm0Mtz3
         hGbm5KdU82J1cagjMcv5i2S/0tRNLV0YOAzCmA/mQA4ZgTjxEHl+7uhe5CCdn2qQmTEq
         Z031UZTKcntz39i8gLvhrC/GMlp+d+B7kQ09MQqgmRQKhRfWVhEHy8fRFAgBiSUkp5jw
         keIjW8efeOtlgieLW8fs4SlTrlzsmuVp3NJbZRi+YaFflDic4MjRKoX3M9EjHdkvUPDi
         wnXea20/FLeSPSrZRxYuLMStLYtpZ7S8Y5/fzerxgputy5TdQtvanMyLlKWbcsouQ43K
         hN1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739213652; x=1739818452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FElwkrT2vJlARiPS4S9A1qo01ZL21h0LeVZcW8aCY98=;
        b=sj/J2FGT0FCjSNIbwuuXjPzr2YnUcyXiXCEMZFt7OTtE2JvoDL20V534lUgF0eqeWw
         M7JkKXkgFLAY2WBoVaGE2t6rbBxOYMayzy4bJoCAubadSv1oPABBsjQFi/zCEd0INV/A
         imL7UJPyQml225SwgKQ9btEa7vfWgDqOFesRGVvb66kRzvV2QGKPBhJtOvnzOx6CbLDS
         jwqKLXOWkTjT0iyLAu/nbYaF/UKMTIQv+3Oz0yaNxktCzLgVxEn8/BHMib44LJ99EYGP
         dC74dNlLZwFftNPHF0Y0bbRzDoe9dqu8fXX8ALy0ZmdE7UNc05AKkbv0lpIxiWQomlDY
         Qbxw==
X-Forwarded-Encrypted: i=2; AJvYcCXm8nErBwKCBrF9Q92FbwSwiZ32eRl5c14SxltruMceaMuJURLWcHVwyMerts6TdZeSQt5s7w==@lfdr.de
X-Gm-Message-State: AOJu0YxCOvIedjqCfTW56dnoBBrLI514tEfRdQkNkNI6rhEmcGHlFOjd
	TgPKQG/F/lwSXVAJ8R/LjpCLLFlV/re56FcMcN9xV7xbWpSKTa7q
X-Google-Smtp-Source: AGHT+IF6Jr20g3FCpUyFuccekBY/UJmAWOs32hgkloW6wk0drQVxsoMty+WQOnacjydYCDykXvIklg==
X-Received: by 2002:a9d:5e02:0:b0:726:c9f5:750b with SMTP id 46e09a7af769-726e802a2fdmr309247a34.7.1739213651872;
        Mon, 10 Feb 2025 10:54:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEYtkQC+uECyGgo+krzT+YXbY6iEgp3D4CkvulIezXKGw==
Received: by 2002:a05:6820:1f06:b0:5f2:d36c:1775 with SMTP id
 006d021491bc7-5fc51a7e0dels2015249eaf.0.-pod-prod-00-us; Mon, 10 Feb 2025
 10:54:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYybDyL6xTtH+qdO8rL6hhu0NgTuHQVqTOT4c37lo2QMSu6ehHE5jpCpKduVAOr3gx/n/oDOw0tSo=@googlegroups.com
X-Received: by 2002:a05:6830:4990:b0:71d:b6a9:74c3 with SMTP id 46e09a7af769-726e8045b6bmr359681a34.7.1739213651031;
        Mon, 10 Feb 2025 10:54:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739213651; cv=none;
        d=google.com; s=arc-20240605;
        b=hjTPeQFAg6leskY3YAXAjE/vZxKkVitNhFBrpUTVmpkDXqP0uoXa79NAWWlhQGGrVC
         jRbSGc3zT4vaKmZfW6TYRtsRdMLmhVSAfCTVrrpkg1npQrxGdIA9nHCuW4XAKU4r22+P
         ubb0ADEIxk7nCcYAf6bBuhZWWuY1KZwJRLxqtHDd2qJN3rp+szsrsEvKS11j0O75aROP
         ebPOi9ne4buLP3KywDfnA6NqJshHTdqnMg+8sXC9J7Mnewa/uF7q7H/SCwYn26WZrb9t
         gpZPo57Em0g95Fu6HKXpbwHd8gxzxDupqq4Vag1CWlLedHqhAGN1/hoDHboOOaJRyEGR
         1Xpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=lb5MvhpLjR41b3jztycQhMa76fKACTOTpukAQOD291M=;
        fh=0Ovo09T/l7iyAM2CZR26Zg4xB/uj/2vRoIXmdAf37Lk=;
        b=Bpik2aQiD69L46e2VGwM4Uc3OeJgzM8BiE9C4qzhUdV0lg3iKbyrDTZPOZPzCIUjMJ
         JUPO34nIW2WxO+ZlERp91Qzyrc7N8k8ZR67BFBAQqLknGIy/eaXJIAebIdTgIN/SV5Bd
         kJ0E9Zwth3NoaD/sCUNvmoeOZOADv6HNdgg7IrEcMIe3teKCcMJgjWk/6Az6XYv6Yunn
         ji/uW1YK4H/mXLJV4Q0pmJrVZ2GhEoCjpFbr1OftcjSdoZhtJcNOKfVomswYtXCNGsHG
         /9aQPaAyUYaKAjoURTKLC6OIJToIf9dwsm+jINKADdMni36revFVKzq58Ns6UHihCVkR
         Y4UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=3K5ArPU6;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acm.org
Received: from 008.lax.mailroute.net (008.lax.mailroute.net. [199.89.1.11])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-726af62d828si380597a34.0.2025.02.10.10.54.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Feb 2025 10:54:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted sender) client-ip=199.89.1.11;
Received: from localhost (localhost [127.0.0.1])
	by 008.lax.mailroute.net (Postfix) with ESMTP id 4YsDJK2K8fz6ClGym;
	Mon, 10 Feb 2025 18:54:09 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 008.lax.mailroute.net ([127.0.0.1])
 by localhost (008.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id UXKEr8zbt9QF; Mon, 10 Feb 2025 18:53:52 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 008.lax.mailroute.net (Postfix) with ESMTPSA id 4YsDHs5q4tz6Cnk8y;
	Mon, 10 Feb 2025 18:53:45 +0000 (UTC)
Message-ID: <f5eda818-6119-4b8f-992f-33bc9c184a64@acm.org>
Date: Mon, 10 Feb 2025 10:53:44 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 08/24] lockdep: Annotate lockdep assertions for
 capability analysis
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Bill Wendling <morbo@google.com>,
 Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
 Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>,
 Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>,
 Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-9-elver@google.com>
 <e276263f-2bc5-450e-9a35-e805ad8f277b@acm.org>
 <CANpmjNMfxcpyAY=jCKSBj-Hud-Z6OhdssAXWcPaqDNyjXy0rPQ@mail.gmail.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNMfxcpyAY=jCKSBj-Hud-Z6OhdssAXWcPaqDNyjXy0rPQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=3K5ArPU6;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.11 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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


On 2/10/25 10:23 AM, Marco Elver wrote:
> If you try to write code where you access a guarded_by variable, but
> the lock is held not in all paths we can write it like this:
> 
> struct bar {
>    spinlock_t lock;
>    bool a; // true if lock held
>    int counter __var_guarded_by(&lock);
> };
> void foo(struct bar *d)
> {
>     ...
>     if (d->a) {
>       lockdep_assert_held(&d->lock);
>       d->counter++;
>     } else {
>       // lock not held!
>     }
>    ...
> }
> 
> Without lockdep_assert_held() you get false positives, and there's no
> other good way to express this if you do not want to always call foo()
> with the lock held.
> 
> It essentially forces addition of lockdep checks where the static
> analysis can't quite prove what you've done is right. This is
> desirable over adding no-analysis attributes and not checking anything
> at all.

In the above I see that two different options have been mentioned for
code that includes conditional lockdep_assert_held() calls:
- Either include __assert_cap() in the lockdep_assert_held() definition.
- Or annotate the entire function with __no_thread_safety_analysis.

I think there is a third possibility: add an explicit __assert_cap() 
call under the lockdep_assert_held() call. With this approach the
thread-safety analysis remains enabled for the annotated function and
the compiler will complain if neither __must_hold() nor __assert_cap()
has been used.

I prefer the third option since conditional lockdep_assert_held() calls
are relatively rare in the kernel. If I counted correctly, there are
about 40 times more unconditional lockdep_assert_held() calls than
conditional lockdep_assert_held() calls.

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f5eda818-6119-4b8f-992f-33bc9c184a64%40acm.org.
