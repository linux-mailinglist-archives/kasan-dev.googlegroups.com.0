Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEFPTOYQMGQE4L53HCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FC4A8AD6B0
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 23:33:06 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-36b14592349sf27575ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Apr 2024 14:33:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713821585; cv=pass;
        d=google.com; s=arc-20160816;
        b=fX1KLtzddphSK2xrDx75/oCkEzoG/0z4ho5VWqRDKOP6dEmXspQea58d2QO6VdsCLi
         3pZmulvJQc5sjO70UBaUbSthHpcyzQOSrzmItVeBnB2Pz9Tp4+zRKsbevzhEqoO/PQ0k
         aD/vOo5QGmPE8r7FhJt6Iplo1DMGJGM2Ge/Tbu5zPDWjtpKkLQ3RGEm5letjlRWqnOKh
         AQgNx+vrCRrxgVgBBD9U04CPrcfeUPbXfMA/eoD9pxjMlazbxvdFE1JwW9LsbAsWuG4P
         UiGmh8Ex+dcUzSDxIqSvwa4o0zIznVshhpAay21MOWXE58CCkA4/uh8C4NjnWS7KqwWV
         GoeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7T+xnExZ2TGBwscr5t93LbmJ19v3SyHhEpE71ntC4qw=;
        fh=7eGnjWcXW6tcoqySeSF6f7l46KWibdBbAqULQHu9oLA=;
        b=1CgmAfvXTMklbZnRnUr1EysYqCk+toovLcv/LWKL1IpPjJfWMGBCYRR974h30pO2k4
         AFeog57IzHEm02mMIjv1flKcVxa496cl7I7ADHtFbe7xSs7t9SoUj7N42iBZnN3IFNJP
         7qN6Q9J7HgIhtoYy53iSpkhndRu3ebxHGrAR8W17ySBWcWNs7mHsFBdDd/C+VBIsVqZs
         lRcg80oWqUqAl0C4BFQKgMO8ruywegLguuRq15i6s9opFw74NnGqUJ0AHdE9uNuIizhd
         ZsHEi9wTfC/0IQeYoZgP6pnClRbvZMoe+SYBIkSPnbvEyLYb4WF5S/fv8nwMtH0gTPBc
         QaRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=biFotF9k;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713821585; x=1714426385; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7T+xnExZ2TGBwscr5t93LbmJ19v3SyHhEpE71ntC4qw=;
        b=ODcKiHisH1RErcc1nuBEm8SucJ8kj2lfeMxJlBNQ7IowDCzIM2yPrFF+sKZtUK5eTL
         2AbPOmqpCiRjlGfacyvE5/s8S0m8lI4QCtFML814sznKAKWwltufC2bfm0bXToy8M3Ht
         BE4ANnJMZF7emUSnZwOrBo8er+Vx7ESTt0WGiIlwDTw7ge76cuE5IuUSd2NJCkg3idDE
         Dt3UDIDipDlDtfSzVILyThayE7cDcuCPVwcwzyI/mKNlPh0LHd9vg8o3wfCUg5o/sRV2
         fBgJSJWfugpxuwIoaAMriridHyXnk6aerKUz8hSveaJbAH7NS3qGa+gDHd3SlUb3TcZf
         61Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713821585; x=1714426385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7T+xnExZ2TGBwscr5t93LbmJ19v3SyHhEpE71ntC4qw=;
        b=XmkbvrRqn57ZKFNnaeyukbz2yU8Za06Vcotb08fSjLhwngNxWIKLbZD8vFefJ7x508
         QNasg4D8tuLHR6wx9ZKuiJPlqQSUUmt9UxG4gCnZSkhLhIbbCAKblmX6PpadTJIPMLcn
         LDhAJDSG0BynomtSej49PJ3wHQVytNlzTYJqoBliTrPnMVENEeTtmmVrRm/ZkTXx+dsv
         HTfGlXW8iuoSNfOXnS7Pcvq3lQMcFAhPx9k7HkEwKDlTS75SFRmIFSb+tSnROWnk4LYD
         NMe+gtVDqkpm7d+8dziGk0QEhuuJhUHyRPRMTz6CTnTXcqlDmKHp6KfrrYCEzBjpxlyF
         ukOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsjWfTLawpYfQ7dUgHgGgAtQ8B1zwtWTSUC64eaAlPhN3/g5vONEWcS0GchUd1LfqrHWZ8cTLBV3SHzDXT8WgbGjNjDulIBA==
X-Gm-Message-State: AOJu0YxsQSIGWGOzFYF6M7VB13Yp6CxfKTTr0mngjLhdiBGWPyAQ4UIr
	AF9r0vJryx2D2XC6Sg6EAu15ecwNmQujuqqGcVR3QrIR7Wwmrh04
X-Google-Smtp-Source: AGHT+IGQBGONdbSbcwaxNytvdKLbYUIJruuQMKptDJldD47eIinT0h6aQlo/49wEBviQ6+UhcLP1zA==
X-Received: by 2002:a92:cd52:0:b0:36b:ca1:239b with SMTP id v18-20020a92cd52000000b0036b0ca1239bmr78069ilq.28.1713821584987;
        Mon, 22 Apr 2024 14:33:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1988:b0:36a:1ede:b31f with SMTP id
 e9e14a558f8ab-36bfbb149c0ls23417685ab.1.-pod-prod-03-us; Mon, 22 Apr 2024
 14:33:04 -0700 (PDT)
X-Received: by 2002:a5e:9910:0:b0:7d5:df5e:506 with SMTP id t16-20020a5e9910000000b007d5df5e0506mr12779237ioj.9.1713821584144;
        Mon, 22 Apr 2024 14:33:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713821584; cv=none;
        d=google.com; s=arc-20160816;
        b=aHdyqAjekXv/goxA+mJ9TKlatXc4IcgwXcsjgri0LTKemyOv7zlxv1/EBHvvz1d4Rn
         LvUcZaTMNMWdx2mU0FzeTDQ7KNIE64ZLwoP1kBqErSHAevXF0Dup9bSt0g2pRfSu9a7H
         MdD7PAxwPdcid1two1L27BVEgjWaAHqmomVDdWGorbhaocVdb9oJG/tkKTOjNzw1MAvQ
         6QhNxrtn1zAV6dJv96kcvjkCjyMkB6yvmBRmpSILbbOm/Dqlmcr7UYFMGq++xbMze0kl
         yT6GZZgygUKU8Oo1mQW7GBJn8vSY/enA+L/9zZK7x5ggCowW+1Gty+O8U2fIDjeGcWZz
         Q4fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DUwsnlxCJQUW+PCZw//UUShMXQLUC5xPB0EJ9AbwarY=;
        fh=7vXUBfeIBhZajighND0JabQYQZtyfxRFM7iIgOFeMTQ=;
        b=0PJ4owxA3S6tcG9i6KZgSC9UsogBZS2NKjvvXC0EYuGdSwkGYSa8YZ9iy3gKiQRXU2
         B2pfkzW0PhtoZ9GFYXBeDHtiubDE0M/pSlWjbQ02+zFNd2HjKa7avDX9GfsO/1RARBAh
         HhDmLGDYFTOmMUgJL/IYONUb+QgVr+2e50ApFxI/EsMLS7Yg6ABelCCcK+3H7fsebruk
         4xpy172xTkUrAZT0AtgrXQe3ri55AEAxjhSQpsFgfxPMthu/ThtZINvnPacNgBD7+Q4y
         HG2MLPQij+uHa+h6FnrYSZl+z03+GyQuVfKNHdJ4qoXMp91cQm8HoTisEyfr7ZQO+phL
         /svg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=biFotF9k;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id ke3-20020a056638a60300b00484954df3a1si842925jab.0.2024.04.22.14.33.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Apr 2024 14:33:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-6edb76d83d0so4133895b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 22 Apr 2024 14:33:03 -0700 (PDT)
X-Received: by 2002:a05:6a00:6010:b0:6f3:1be8:ab68 with SMTP id fo16-20020a056a00601000b006f31be8ab68mr1995998pfb.32.1713821583339;
        Mon, 22 Apr 2024 14:33:03 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id fi33-20020a056a0039a100b006e65d66bb3csm8293286pfb.21.2024.04.22.14.33.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Apr 2024 14:33:02 -0700 (PDT)
Date: Mon, 22 Apr 2024 14:33:02 -0700
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Subject: Re: Weird crashes in kernel UBSAN handlers under Clang on i386
Message-ID: <202404221432.C87399A@keescook>
References: <202404191335.AA77AF68@keescook>
 <CACT4Y+Z2T+A2xwZ=MOVnoUewAxnTcQ3B4AcCKpsUyp2TFSX8Ng@mail.gmail.com>
 <202404221236.273AA69C0@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202404221236.273AA69C0@keescook>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=biFotF9k;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433
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

On Mon, Apr 22, 2024 at 12:37:55PM -0700, Kees Cook wrote:
> I'll keep digging.

I think I found the problem: -mregparm=3 isn't recognized when the
handler calls are emitted.

https://github.com/llvm/llvm-project/issues/89670

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404221432.C87399A%40keescook.
