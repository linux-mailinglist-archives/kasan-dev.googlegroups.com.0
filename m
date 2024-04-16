Return-Path: <kasan-dev+bncBCF5XGNWYQBRBZUU66YAMGQEHZ43HFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 88F7D8A5F70
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 02:46:31 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-36b29dda7b3sf2197015ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Apr 2024 17:46:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713228390; cv=pass;
        d=google.com; s=arc-20160816;
        b=a3Fjb8JmqJsYD1HKMhJkawQikkOxEQYFwRsPnp0qc5rgtpkR9My7UKZE9vRwvwLn11
         FR0t7r2C/QNc53ykW1L3Rn0ObmjhuOOvt8XLHA8p9etXrin1mNrxXviPGombpD66FCFJ
         g+XT+pTsKKXsjYdTmv51vf0VQSmxP+sARHZXM1Z2OfDLumNcs314d+f6nNWqhJkGYxXe
         roY6BpINn7NkPyvANETiDmdAXkfy19rRiNeP0r2thIqMSVg8QBBh8B3BOifR90YJrRRO
         7fMO/iDqni015WyQFyb6UUe2a4w/8KLwxDUfKwBlHewEbOJjPryjrif3xJGl9BelAaXp
         k0og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tpHJdWhe/MjrjQsk/51G2B+a9IBfDP6DAph8SjhbOTo=;
        fh=4ZSNi2q52NMH7D/5M4sgEPSrwQUf9UKwku+wq/4wIGI=;
        b=dK+26Nk9AnmPY2znramgmgGbcZFlq3bzmJ5I6u8CGQ4YawF6/NuClGRGxdoGZIJvIQ
         ew+D10wnRRe9o0t8FSk6MB4VbdryMbbPJnBvJw84jdNqP38URuevkd1jd0zV4HA3e68X
         eFCXIzTzUpLWx529X6A5f8NS2MmAT31LltlXyJ0Dbv7lGjC72nMLNV3BPl3tHwLmcvxa
         gwlQiKEifmFXhcl+CZVyzmMkGn8opnY18o5bHNH7BDLyiCqMzjgQ5LNRPZFrlTkCfVgL
         DRBSjQLYodoch2QHvFnxC94fqA79WB+Ls3/rHnPfdD5vz9sL3jHoCqc3apPI+MxaOVRu
         005g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="dhrD1/X/";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713228390; x=1713833190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tpHJdWhe/MjrjQsk/51G2B+a9IBfDP6DAph8SjhbOTo=;
        b=VBxxFb8+SaOxas0qjR6xr6/V6SOCoiHI6hWI4/OYX/CcjSlIuZC/WJILfogbySeF31
         /VwLEFKxyeOUUHbrfmuk0g9s1TYcsDIUEvtP4KP9hdAKr9Xq9cHjNLXrjRBkiKCq/8hT
         7RoIJvxvnnCW6xmLDuhDwQVSL0vTJxosQqNgkzA8kjlrmQYLz+DyFJTgjc31F1AZbAfd
         8z0vR5CkwAHyOqdUoUuAkfXUn4bONJQSCey5eKMacZ5CIWbdLj6e5kVJmCJdDkudAGdO
         GbFRRb0aYxUKhnZ1CyJfBOPGIFSahyEgjvBFHv/xyQAjbZWWDFIG0sUqthK/gk+PQA8E
         7vFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713228390; x=1713833190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tpHJdWhe/MjrjQsk/51G2B+a9IBfDP6DAph8SjhbOTo=;
        b=bFrZ4Iin6J+xc2Y9mF7pitfMnXN4qGsRYOUkb3TOdfD2sTyrv3t3/nGcDZL0QVaOsV
         z8VO5nol7mDlM9TSU4a4vZLZ9fj/YGek74ahzkcXNWdtaqVfgrV94TL5EFQYBsfSYnl8
         fq1Z6uPvFKCfW3PmsT5baYlAgiX9oqRws+DiPv9G1ATBKNug004C65mUnEzsSH1rHKTc
         GpLzFuljS7Mw5XwSwIA3FKV2TL0RiOa37RpKeKxIk1aGy/q1B0//RC/EY2Uc4ENH2I0Y
         uMigBwERF1smOgj5bZJS4OBt4Kb8OCi8aqcw0+WH52d6KvIiAh4Ccsn1KwfA63/iY8Vy
         3deA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVQHVCnwN7b5kE5/ClJhUmIEjFOO4bPzek9+KIxAUXIU+h7HySbKn+Rts1HDXpQ2//mOQcHevlVlaboDbd1t1d1IlB+Jg57w==
X-Gm-Message-State: AOJu0Ywt5ewUZY4fvIov8To11QdOlIJu/lOGjjlReAXXffpusAy4fYgW
	9ehIQLawskJbDoW2KHsGLP+hDuypbh3EIiGYvL24idTD02QsHCp1
X-Google-Smtp-Source: AGHT+IGsrfN/gNpQA1klFqhrloinbeYp9oYQVjzuKdtUvoIeZ6Z1P9S389BHwIV/+2O2hMlRdygjfw==
X-Received: by 2002:a05:6e02:194f:b0:368:cde6:334 with SMTP id x15-20020a056e02194f00b00368cde60334mr14252582ilu.18.1713228390155;
        Mon, 15 Apr 2024 17:46:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d12:b0:36b:2227:d442 with SMTP id
 i18-20020a056e021d1200b0036b2227d442ls849708ila.1.-pod-prod-08-us; Mon, 15
 Apr 2024 17:46:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJJaI05x70jsbJm6kIJmFwV2pihxqbRqABJJGdm5IgzeXSsC5RaPn6APtCJoazCsFqegsSzfSTUriDowd355XomF8vr3tQFOj1Bg==
X-Received: by 2002:a05:6e02:17c9:b0:36b:147c:f7b0 with SMTP id z9-20020a056e0217c900b0036b147cf7b0mr10384155ilu.29.1713228389318;
        Mon, 15 Apr 2024 17:46:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713228389; cv=none;
        d=google.com; s=arc-20160816;
        b=gPtj8xxZQFjvsspV2/cflfS80k/+ltY1fiMmw1GJPwVV3TSVF/53vp6LxvckTLPeMx
         3p5yAlSbADo4rAtytaRLWNZbkwj97OCVbMk2F8viAFgiUA3oUHJKsy95IxfAiqyamNJl
         x4DdcrEYaH5BAB5eaQgyRm38cjMFW3P5j5QdspW0q7Q0W1hrCdFNABN5lgdome00Gmua
         JrZFQUZvUlsdrA2Nl8vptX+05bK2tl3g0IoLrwMyjeo8a5Z8Hn1WwFSgpn/z2viDr81t
         MTJIh532X2enYZJ8/2jPzzVJonLL7VQ0YWFBieA/bdXod81aSf5T+UWN1yHxM6/Z7EmH
         d0ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SarbV9gzd7Ext5uREk+cO+VjFEa4L7Rs/CELnpCJsv8=;
        fh=rRgfP6pmfKHSZiEGtK52YlnEjrGmnXgQv6E9r1bVk9M=;
        b=EKXHDxeaNO7B6Bq78H+s+uTt2nVKpHmmqm9R1ZeZNIGTEW/1tkcyMZ7HRNg58f7uBX
         /EM0lVXMcswKLMjUFx25TqqtmVdklWWLIYQhAZf20WAfUsEZUjd2qo3H5nnaRe8+mVHY
         QrtYvP/No9x4zexCrmEgKI83Ff9iwSEVwpIpY3m/iu4SQUfD9MKzNiScvXYPSmZ0rcad
         e6Cxp+y6mtqwqM2Gsgi8SkVFR3DEuD1G3hydmWX2Sg2N8cKxVeTmorEDS2/JI8cTmrzK
         KRzP0zYw/yyF51z8cstcGQ6V8GIzaL46Oodmba+JOK1sK+F1wDDmIgixUDw8T3W699hP
         IP8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="dhrD1/X/";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id u22-20020a056638135600b004829305748esi751129jad.4.2024.04.15.17.46.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Apr 2024 17:46:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1e6723c606dso13429595ad.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Apr 2024 17:46:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVqa3J+GGrfydP/pFwNfCG8Q95n6Sfu3IMCGZj83KhjjFMT0H+QUuoY58bady2rqpdRatZONEAaBqMWAj+1KqVWLqoSEXVXqkmzrg==
X-Received: by 2002:a17:902:82c4:b0:1e4:b4f5:5cfa with SMTP id u4-20020a17090282c400b001e4b4f55cfamr11411241plz.27.1713228388653;
        Mon, 15 Apr 2024 17:46:28 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id im22-20020a170902bb1600b001e3d2314f4bsm8688355plb.132.2024.04.15.17.46.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Apr 2024 17:46:28 -0700 (PDT)
Date: Mon, 15 Apr 2024 17:46:27 -0700
From: Kees Cook <keescook@chromium.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Marco Elver <elver@google.com>, Justin Stitt <justinstitt@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] ubsan: Add awareness of signed integer overflow traps
Message-ID: <202404151738.AC6F6C210@keescook>
References: <20240415182832.work.932-kees@kernel.org>
 <20240415183454.GB1011455@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240415183454.GB1011455@dev-arch.thelio-3990X>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="dhrD1/X/";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Apr 15, 2024 at 11:34:54AM -0700, Nathan Chancellor wrote:
> On Mon, Apr 15, 2024 at 11:28:35AM -0700, Kees Cook wrote:
> > On arm64, UBSAN traps can be decoded from the trap instruction. Add the
> > add, sub, and mul overflow trap codes now that CONFIG_UBSAN_SIGNED_WRAP
> > exists. Seen under clang 19:
> > 
> >   Internal error: UBSAN: unrecognized failure code: 00000000f2005515 [#1] PREEMPT SMP
> > 
> > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > Closes: https://lore.kernel.org/lkml/20240411-fix-ubsan-in-hardening-config-v1-0-e0177c80ffaa@kernel.org
> > Fixes: 557f8c582a9b ("ubsan: Reintroduce signed overflow sanitizer")
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> 
> As I mentioned, CONFIG_UBSAN_SIGNED_INTEGER_WRAP needs to be
> CONFIG_UBSAN_SIGNED_WRAP. I applied this change with that fix up and the

Whoops; thanks!

> warning now becomes:
> 
>   Internal error: UBSAN: integer subtraction overflow: 00000000f2005515 [#1] PREEMPT SMP

Perfecto. :)

> So:
> 
> Tested-by: Nathan Chancellor <nathan@kernel.org>

Thanks!

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404151738.AC6F6C210%40keescook.
