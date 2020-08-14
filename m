Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGHZ3H4QKGQEGFPP2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 208E224494C
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 13:59:22 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id mu14sf6402814pjb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 04:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597406360; cv=pass;
        d=google.com; s=arc-20160816;
        b=jooTmNj0LIW8gABU3sEpGjJ9zYjXiAVZTrcZ1a/WCnxP+UDL7cJwlrDR32CMuPc4fT
         pK+QQ8+TEKoeF40pa/tWZpCeJrdRaehwtYdVvuXYuEdHjVV0CriO1FTBMXMxLvsA2kiX
         bUKx3peSwJsZUl+EgZgto0D07AKMrFsUu60/ljtsxsZ8j8wlR9p3VQXzKeH80FNhHebv
         l747vLn0LKN4cUhA/rO0BHO6ga3EtBqfTTRlB8xx4sabGdwj8544SQi7jO/MAyFmiS8s
         8usg3Q5dnJmgYM7G0o8J/DTqmy46zWJCLmadJN3izs7S8GIOS58XzllRBFOSEcHfd4eT
         sGag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Cw/RxQNibRdPX19XYSJNQxu0vfPPlffNBej2TJGJ1ek=;
        b=cMiAAfnz29e98xnsMrKrLA6WM95LS6XSDccpUS7d3j6oM7ifrXc6n2DYAHnzpmrqCt
         TKIFT4yX/qIpAHwmKkVsF/hBcEYWTR+RqB+IgD65ifItexyC8KNhX8WPJomyGhBqA0jP
         Iqbzpgy8CbvML8axpE6IfMPlWR/pK14/7MMz6lYhADZO8+/qD/tVwzIFVPG0Zs+80s6H
         k44/MKs5mVvV49CKbwV6pqKQ9ARv93nfDWEl+CM5/FJ5jot2sQyFWYTZICF7t882WUS4
         SIOHCQGZS5LG035I2PY17jaIYJYOg6XSUn1Y+o/wPtSTV/89FM37msOyYLXcciEzeTXO
         9yWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hu6Nw7Hu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cw/RxQNibRdPX19XYSJNQxu0vfPPlffNBej2TJGJ1ek=;
        b=PVNp+KXqpeYZlcWRlqsDOlbuM7/uZQ/tutJp4ZhqWoUY828CF64p5TNqd+rakyO1mk
         JLBqeluLr112mXjDObXhaDUukx0/2jB3devwoer5lhRzVrOpbRQvxSdGVIYT90GwfYnO
         Hn2oXIKuS+wautfaL05hcNxtglkdPQRHL/bYxfW1vHkOURPJebb0kqyTsu5Sz2FRTE/K
         H0J3V0/pKEhZBd7jIBGHpivjm+HVliUH4ko/xUdVPCMlb8q+NVPKg4TDkV2bGb2pSL6h
         r3AMUAeVPmfGRnogt1LTb7dEWnFyaRwlZ+FaJlcZtxtUOo4VHnWN2yhfhtoHwhu4WRBr
         veCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cw/RxQNibRdPX19XYSJNQxu0vfPPlffNBej2TJGJ1ek=;
        b=Q0OwSgf8z/eKxoy/qv9KbITXWFy2JqkgFRLerC4nhn0ZZ6zN9BfSwZjw6LLKEfmHqO
         BQshiCCsM2DKhz5VYdkn3REsLIZHZwONnTSVxbFe9w/XSP8xghap1KwUHZXlWCC8Fni4
         iRIJY+IzdbRifjwjWnEn22BftwYwzH5CmnCzvffKOzlnC1mL6L+73no//QPRHi5ipsdN
         6Kh4M4tMjAMLpszxgdIunUXiPzvCf+R9UGok73zRa8UXPVVEM8++4ZKXaNK5lPP+TY/k
         luuJfJ8JrY7nPlcYxk2XqQb2xPJzUZvetu8WdjNRDM/KhIbiKvvh7ajZqsaI6bxX76bP
         MgbQ==
X-Gm-Message-State: AOAM532LR7papvJjkD9rjkploP0jCrGUfFt7KXVXee0Y/tsDPk+Unst/
	GEcOOQpSxmA7hsYno3zobcg=
X-Google-Smtp-Source: ABdhPJwu4MF8ZAq8UOv7HJ84Kza777i5xbVhKtuvtwTjbXTqqvGQjX/VwTdKVgQp4xgyIlabapyMFw==
X-Received: by 2002:a17:902:b681:: with SMTP id c1mr1813349pls.10.1597406360637;
        Fri, 14 Aug 2020 04:59:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3367:: with SMTP id m94ls3578439pjb.1.canary-gmail;
 Fri, 14 Aug 2020 04:59:20 -0700 (PDT)
X-Received: by 2002:a17:902:221:: with SMTP id 30mr1810570plc.222.1597406360210;
        Fri, 14 Aug 2020 04:59:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597406360; cv=none;
        d=google.com; s=arc-20160816;
        b=eSPIoDz8YwclCNxOJ9I4fVi1S9kAhaB+RI5Lw9IBIK97KlbOl1o3pe1wg62mww4WI+
         BtIb4QX6NjxMviYr4GVuYzINv97b22YFj0V3ukJzLYo1dHVIuzLim+nzn6wFkGLd0zSk
         mpOCPclfEK8lGQwMEfL+XexzK1N+soTwMe+0QGdeBLh4sUhJuJQSryZkZaoP2MJlnigf
         qJVhqJeVi8irbYpfWR7bjetq3Wo6XW4KkiWHLh48S3Knjls5fRQRFz+j7LTcu6LEPB3y
         9U9YTJGQrsLixy5G+lmeze2yYznASMKBfk5xa4WKuL/hLRJOWryccgmbRqbf8o0pIUZW
         /iUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JH6kRqU1JrNcyy+wqdaUc+Qi4AywqVy9VYsywI2jKC4=;
        b=GatvVAa9G0FT1FCqO81KUBh6uO2iNM7BlN9jfJtKCpKPssMlulDFBb+tFZyA9qPxI2
         KOY3h09SlaEACO93MFJkDLVLIv8Ywvf7dMrxEmUDx5x+12lENtvIuSV7st5o/YA9ckdy
         ChkejKItkt/ys9m/7xckQ/IIg5iIL7KYWToDeUbBXZCQUin2tIqAituJx19+L3qXoahO
         QcxxmvYtiwFX0v0r1xMUvDdQOXW2y4WnejOcrKd5VNxm3v0FR3YXNtNf3XEaaKojY27o
         oXvce7wckINQ/RQfqe1cNS5esTZg3i6RDM3SVy212o38uKcZTyuzyc0q3c+B1sBDDwQY
         OOPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hu6Nw7Hu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id l26si453049pfe.2.2020.08.14.04.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 04:59:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id x24so7366958otp.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 04:59:20 -0700 (PDT)
X-Received: by 2002:a05:6830:1612:: with SMTP id g18mr1480092otr.251.1597406359387;
 Fri, 14 Aug 2020 04:59:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com> <20200721103016.3287832-9-elver@google.com>
 <20200721141859.GC10769@hirez.programming.kicks-ass.net> <CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ@mail.gmail.com>
 <20200814112826.GB68877@C02TD0UTHF1T.local> <20200814113149.GC68877@C02TD0UTHF1T.local>
In-Reply-To: <20200814113149.GC68877@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Aug 2020 13:59:08 +0200
Message-ID: <CANpmjNNXXMXMBOqJqQTkDDoavggDVktNL6AZn-hLMbEPYzZ_0w@mail.gmail.com>
Subject: Re: [PATCH 8/8] locking/atomics: Use read-write instrumentation for
 atomic RMWs
To: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Hu6Nw7Hu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 14 Aug 2020 at 13:31, Mark Rutland <mark.rutland@arm.com> wrote:
> On Fri, Aug 14, 2020 at 12:28:26PM +0100, Mark Rutland wrote:
> > Hi,
> >
> > Sorry to come to this rather late -- this comment equally applies to v2
> > so I'm replying here to have context.
>
> ... and now I see that was already applied, so please ignore this!

Thank you for the comment anyway. If this is something urgent, we
could send a separate patch to change.

My argument in favour of keeping it as-is was that the alternative
would throw away the "type" and we no longer recognize a difference
between arguments (in fairness, currently not important though). If,
say, we get an RMW that has a constant argument though, the current
version would do the "right thing" as far as I can tell. Maybe I'm
overly conservative here, but it saves us worrying about some future
use-case breaking this more than before.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXXMXMBOqJqQTkDDoavggDVktNL6AZn-hLMbEPYzZ_0w%40mail.gmail.com.
