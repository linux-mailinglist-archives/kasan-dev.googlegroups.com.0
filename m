Return-Path: <kasan-dev+bncBDRZHGH43YJRB7PHX6CQMGQEEP3CLDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 86159393650
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 21:33:23 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id g13-20020ac8580d0000b02901e117526d0fsf788926qtg.5
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 12:33:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622143997; cv=pass;
        d=google.com; s=arc-20160816;
        b=DF7lUAhOK8vepcr0ZXJRXn7dntPZorGMC2SIU1iC5dhhbqUNSTAMPnpiefK08J2FfY
         /FXoMW8waEnevKD/J/CPKu3fYvuqgcQ1L9lSBPeDcDdAIAXQVRXOmKg/PK1zJMwX/uW0
         FSyp0F+C5009PvD5WSk1Z/qf8WAMsfG4ScRvZ6AJlEjJvcU8DGlN2mlofrBzj5DDRwHq
         VnpxofnyvdUclFcOYu4okPrN+SQHJZeFwkxxpaz9M4RZANrVXuPsxr7lx/SpVBxXVwgi
         nt5zmE0iyyUiZuwlJ8E0kpYsYBRESfSQYODB22FH9Aguwfo179GPlSfP9X5nLgrNsM+C
         kzEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=QW3RuxIga7Dux2wysTBgRfXRYLSh3lWgQuZS0G5YXAU=;
        b=RBRZ/KQwToLdpY6pFcpdpGiZ96H8UbXrRMTYy5l6owSRqF9iSA6wpZcowolFsjYbo9
         +qkDw5tCjVAts5ranvFuQfJOA0pktpEFgBljWteohxJ9MRsFoY3qBSUFOf/70cqeUFCf
         dErNAZD6orxuLArPLmIUa8xU6LHdmJjqwXrMFsK+nudjFkUbIcXMFI2sQ6G73vMXuGl8
         X0zm/4vJg86r+nTzZY2mC2mE8DS+fkspHLdwGFhC+MPw3Jaxik8EoGGB6FNJ4H188K4y
         J+hhM7TE5rRo2b3MKznZpRKp6/CwMoEH/NjuNVCrWC7edej7/ToytEFewhWtMkr2JqRA
         CRLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WRYZgK2U;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW3RuxIga7Dux2wysTBgRfXRYLSh3lWgQuZS0G5YXAU=;
        b=MgewBmmpDrqdEeLBd251m7HAOYbNdfRKcame6EwoGsf4opRzrqt47zNuSNQ7lwPEBz
         kmJkUSzDzsgXX+xbgRdfu1Hpa1GrmpR5umKy9cAiNXowTYMgW9W3D+Kku54roJrVm0Qw
         adeH3ThCKKxuL44nYeGcLcU/kqaZRaRBYz6HSCKX1NZKoiwDjouk+vPstBsS33onXiW/
         LFJFTVpagbtt8VoFDlUsfOW9Fjoz9f/zwTRZX7UdykamD2+Wvh2VHrhy8grvz9DkZ9OT
         gMkmSt9jlWkq1xb1sTPMDrgcsEZUmpVSDfakioCsozjQQ07e1Y/Ffw+N7al8b4jNS2rD
         2j7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW3RuxIga7Dux2wysTBgRfXRYLSh3lWgQuZS0G5YXAU=;
        b=Emn8zPCUsLtb9OsaoLrS0otkcqtBcGsxgo8EGZ4cZ6U1Ipk4sqakYQLGCmClicoQlW
         l17qRazcXI2ti5yFCuqkzs0Y7goOh2W4bn70fjEw6sbfoyqb05DkyckgTCSuwhY7AYUG
         bDXxcTpMDHF1N+NqzH1SOFlVuUpYVZFigb63Kzz5xQ/dMv38U6SGkX0VBFWmegvnaAyv
         E3ySHS0cT4jWj3+IghTvx91JFITOTZ2/u89B2cCukvgSgLvc8ETp3HC/RQgZ7EiaPpOb
         104WnK2Ixl+f+rK2snLFbjFu7yMGcixrLisaoHku9LawzhG3Nr97dG3Uha/rHPX0qBnm
         7JGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW3RuxIga7Dux2wysTBgRfXRYLSh3lWgQuZS0G5YXAU=;
        b=XPJgg5iIkCRks9FniwZFuzDIbtnDE8wUxN0pOctqo/mrzilM7JID9xbBSvy8gsfti/
         JnKI75Hlzp4VmnFPHj2e1qFFxN/ry2XNRx4jG6U0PK7sjqCSNt2xdrprCD0rbay1WkFp
         Je3v63YUmYXCQJz8X6n+udGN3ZATCMF6IoY83S/24PLJS/BYsgYxdnT1oIzfs0BQA+sb
         4GA0GaY8j1N+uenBRZfL3GaDe+gilHqUniQn/HJOMUNQaNdkDCibRfrDZ/+JrbzUg1YW
         GcikL51Lvcd1Vt6Wgb4D88IU6kPgmjg6NQC0ovpaaQQyUWYtnZyHDTHqBsbBqMsBn/vH
         eCOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JD3UeACK1w1gcH++Le4Iv0y5a5aQJj8TWEehEHEwbNLgistHC
	eJDDhatSZVqCbYLtQ8496os=
X-Google-Smtp-Source: ABdhPJyiJlwc7vVYJv0xLFz5irnD9f6v17oot8ZhStSdfTqrRI0zUfK8kuEe+c6yT+wT1S3cz1Ht/Q==
X-Received: by 2002:a05:620a:7f5:: with SMTP id k21mr85935qkk.129.1622143997184;
        Thu, 27 May 2021 12:33:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a5ce:: with SMTP id o197ls2774796qke.11.gmail; Thu, 27
 May 2021 12:33:16 -0700 (PDT)
X-Received: by 2002:a05:620a:146d:: with SMTP id j13mr53169qkl.493.1622143996701;
        Thu, 27 May 2021 12:33:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622143996; cv=none;
        d=google.com; s=arc-20160816;
        b=LAK0YNPrNU8nYCeCLu9Fv+BhgyQ1HP9mqwGqP4Ro48c59QAEHyiaOp5oHifj7C2Wjw
         FxP4iStH3EkhdJ4bPYeJm4sMQz/GIaZOAhqPg90j+YmDlqH9RY8yysmv4h0KvkSci2VX
         BJta16364sj/SkShduVep45M6whfm+jrmRaFYhpZqicvsxt7J4GYS1KVE7kl/UwG3dzv
         V3gkRxb50Db72GM6CT7Ip4tfbyfbsJObOzNu1iO4lBR+EP51XQOhvAynazWU8R4QRWti
         o0Niud6S7VQJwpUO+IMLsqlSA2g7liTMIv0bUxbtffO3dn7wkeE2DwFwxBUaKm+TMppo
         CGIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kdIhgUoE9F3zBlRjdECMCVLSlqqYp+VNMOtcyHqGSuA=;
        b=tN8dV+/CESF3ABV1bV67X81paZOULvJ6shJOof9lXWHtLKMO2nXEscQgqHx3Gi6567
         5I3pvjymGNWoM4jA8caEQB2BdGV1YYbuo6wgFtmor0LcxIHRTlmHKQuSw2EnKt+/ABHQ
         PqGZ1TB0ZKs/Y4OrMlh6PCdVkgV7hgyWqp40kj4+X6s9KWknZ+c8QNYNiNkwUBCvU2St
         UIYJxVVqm/l74mg7oPEpZ6XCUz+hknJqVnqLgbJYul9p7bQ6B1BMu2WdR7jnfUxxuspF
         gEAsn0Fghq8hlIvD+nw3RxueNHbAvbzgVl9lOqnUjVRLtRb3RE5NFmlDZzuQqlpI6+dy
         wDAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WRYZgK2U;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id o23si317223qka.0.2021.05.27.12.33.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 12:33:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id f9so2247760ybo.6;
        Thu, 27 May 2021 12:33:16 -0700 (PDT)
X-Received: by 2002:a25:7909:: with SMTP id u9mr6984300ybc.22.1622143996446;
 Thu, 27 May 2021 12:33:16 -0700 (PDT)
MIME-Version: 1.0
References: <20210527162655.3246381-1-elver@google.com>
In-Reply-To: <20210527162655.3246381-1-elver@google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Thu, 27 May 2021 21:33:05 +0200
Message-ID: <CANiq72mvSkHULFVSDr6A=pv+2PUzXxzNFpjmKJGt4tJum_LEBQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: add __no_sanitize_coverage to fix noinstr for
 all architectures
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-kernel <linux-kernel@vger.kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Kees Cook <keescook@chromium.org>, Arvind Sankar <nivedita@alum.mit.edu>, 
	Will Deacon <will@kernel.org>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Borislav Petkov <bp@suse.de>, 
	Sami Tolvanen <samitolvanen@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=WRYZgK2U;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Thu, May 27, 2021 at 6:27 PM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
>
> Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
> if the feature is enabled, and therefore we do not require an additional
> defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is

I would put this explanation as a comment.

Other than that:

    Reviewed-by: Miguel Ojeda <ojeda@kernel.org>

Thanks!

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72mvSkHULFVSDr6A%3Dpv%2B2PUzXxzNFpjmKJGt4tJum_LEBQ%40mail.gmail.com.
