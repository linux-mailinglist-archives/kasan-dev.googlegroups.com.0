Return-Path: <kasan-dev+bncBDAZZCVNSYPBB2FGSH2AKGQETYTG2VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id E9FFB19A784
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 10:40:09 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id o13sf6215780qvn.15
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 01:40:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585730408; cv=pass;
        d=google.com; s=arc-20160816;
        b=XOW5h2/h9PajFscByMP6qBzrjD658IVzV8M+Y/OaNTchxl1i8skvUldHWhjuLhsLPW
         G82VPH0Pzj6h1cJ2uSF2W0PdlFbBBY0mc2/yxxQj6Mk+Y453g8BnRq3eYRAqMYTDB+EC
         COwxgwn5Cx6GJXsYDNnkWwvjBl2Ev477JZlSI01Z5/ZxcjwXZ1Z4EdjsFQIsmgtiXCS5
         dIMmlEfTZ/KiAJKq7euyvH9VY4Z3L49q7cN9yDvAAUZfDVYxsals3n2nxqoVN5+OTFCc
         vwD10bkvG6Xx/ePHhW78/AdG7rsP+MEbku3LrMdS4SlrHB+SyvqrDnjAI0g6v0u9iijw
         KFaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/OV4nHcllhUtsCGNOBK1kRqE9prmazs0z3I307kaDIQ=;
        b=Dd8CNcDYTgI3WVyHLmjiKZfBxDFHzf780PrglZSmNjtk4R+zm4zAY/0Su1NaeDv/sq
         BkSkIudIqpJ6G4TXcZkgG3xH6F/eOQoRj2XpoXyzhHEBMTfVCj5EO/CrcUxwkvpywusu
         M2eloyXHsXLDWWQ8P3csgCO7xc1QTpRxOs24u1hQpgE76gJ1mr7Gk/NEH6IWIZ+H8qbm
         sj69AmKHW7dhPkDa3CXb2twMX5WWmMQ741vs4yHcHY+Pncrc/ze8K66jR9CocwNve3rG
         v7E8MEhuNrHhjfZ+0aZdh/dJbWRuVFF4QDdlGC2UudFLLldoIFU3qQavBDNSn3HzbJN8
         6nRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=E69v0NqT;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/OV4nHcllhUtsCGNOBK1kRqE9prmazs0z3I307kaDIQ=;
        b=eSt7m5qnos/mXdYMUZIEU+ty9cet+8G9UbEHklbDfWYYVqdSrRABMxxxaatxlPVRle
         /ypwGvBvu2EZXfd6bHzgntudGW+nl0SbhKHFU47tGCzX46d4tKfyzmvE+b1um0Wwyfb9
         wBONk3rP1q/o9b+NL4TJbOpu8PxQL5x3/h5LfWL9Y+rttwvlwz/ciweNRsNX5gtWW2i3
         DMR239V0WWsSWc7qSSzNashJxsa0t0LIc9ge4uhoz/umvIMBP5atxp1RauH4EqiUGD3G
         lGlrmPClPQN4OYKOfzwIrpboIWDZUICdpNU9gjLau4pJGrNLeMl86Fie6y0pUU3E0+uy
         WvZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/OV4nHcllhUtsCGNOBK1kRqE9prmazs0z3I307kaDIQ=;
        b=t1V1ORBHNjhZ9f80c2pSkiS+rZQIkN5/t1yX+t5mFWsWSv22CzUuD/MGvxRT1OfUXa
         fAOQknboNQpCMm1NshZh+xSvKbSshctyw/sVUYM7PPCTZHkPcEK8ir/5FHkkxQ60pPhH
         RicwTVKqa54+R9cT66XUGL3ir/9SBbn9b6jbg1TLETsq4x7S2B6FlDxMUGANR1d6TqwZ
         2HhloFJOkny9thHvI744grVe0vmD71r76ke1WOW2AFIGcuJLhtUIU/TSpGkw+z3LsOge
         benKx9CvKlWA3n/tLOxaQl5dmKHYAAAnsSwcuOvtuwJeiSTzmgp2zuOGm0UOwfO2oCmY
         wvow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2Txl1ViAYVp6kCaJQ1AKMUTEwIoER4f0y40EWLrBqpJcr/h3pz
	4wROKSTB6NYR0KfIZYP0OJI=
X-Google-Smtp-Source: ADFU+vseXu5SU75XeXkgFZ6C+M37rpp3T0MAsEefJhKGBoVn8yP5v9LohmgB1KIsG6xM/vetgwdGxg==
X-Received: by 2002:ae9:dd02:: with SMTP id r2mr8199846qkf.180.1585730408603;
        Wed, 01 Apr 2020 01:40:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6487:: with SMTP id y129ls11789945qkb.10.gmail; Wed, 01
 Apr 2020 01:40:08 -0700 (PDT)
X-Received: by 2002:a05:620a:84d:: with SMTP id u13mr8221787qku.94.1585730408247;
        Wed, 01 Apr 2020 01:40:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585730408; cv=none;
        d=google.com; s=arc-20160816;
        b=DkEvxNS3aIzWSe3zHRgx7cGUivVeA8S5UQjBCgiEmvxXMHOFtVHboEJXLwe9MRdWNG
         0/6JXqC7dJJuWW0Q4QJDaCivbMvzjYNmBv4dfMthdqL6wIZ4ixVAwOFMx1JlmKeY2LGt
         ZtMH2sIU5xRsn7/prjG/Kr+9tr5epH8t1Zq1XjtEeQvRDCANzr8IMkH/q3llwJt/hg3B
         5sbfV8ga6j7HsDKHQbi2fOX1DLZoyitfGP4nAAP85k7w5SHRhQwIINn+h6+mpBeVPCUf
         S0gleIh9gs1DaYXDylenvcKFpadgkkLTClfzsbnRTBgx8zrMlbZy6pkpLtC+qxMqj7Qr
         uuqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HXic2+xZ+QAaHobL1HuqBoxft3dd4VTNcweHpAIQqH4=;
        b=E60DEfbMQXu2cu3pZVTkzTH1wVqHo0ny+Xz/c0SCbJYxxsrYmwRLh32TsI5w/mtCrY
         d1vvQ4ovt2n5r2rdA4tfmpJFqDuaya5Cc0FJBl7dp16Cd/aqYj0bTJFCVki7iZJOGU/A
         qqZDB4fAQ/CxNOeP5CZoWpg6HHcTqnrMHRWl1e4sI9hINjKUaxW5c8k9tRvSdoSwwrSG
         YooCVUj5XNP+UNm3wkDcZlUzV/QeMdPuID2LDvqpsZLHT/CW0lvN6WtQ6M+HPyaXf1OO
         WZgW3/zvEOOq9ROmwfm7q7tEb1X2lMFu6zwOLYx+QM0+u5YDB3ph5p0ne3BtpneoFm6V
         4rqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=E69v0NqT;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j56si125280qta.0.2020.04.01.01.40.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Apr 2020 01:40:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B00B72073B;
	Wed,  1 Apr 2020 08:40:05 +0000 (UTC)
Date: Wed, 1 Apr 2020 09:40:02 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Move kcsan_{disable,enable}_current() to
 kcsan-checks.h
Message-ID: <20200401084002.GB16446@willie-the-truck>
References: <20200331193233.15180-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200331193233.15180-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=E69v0NqT;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Mar 31, 2020 at 09:32:32PM +0200, Marco Elver wrote:
> Both affect access checks, and should therefore be in kcsan-checks.h.
> This is in preparation to use these in compiler.h.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/kcsan-checks.h | 16 ++++++++++++++++
>  include/linux/kcsan.h        | 16 ----------------
>  2 files changed, 16 insertions(+), 16 deletions(-)

Acked-by: Will Deacon <will@kernel.org>

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401084002.GB16446%40willie-the-truck.
