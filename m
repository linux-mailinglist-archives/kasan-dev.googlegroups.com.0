Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYUE2P7QKGQE6KNGSUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 06C6D2EB39E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 20:47:48 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id n108sf547723ota.5
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 11:47:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609876067; cv=pass;
        d=google.com; s=arc-20160816;
        b=KoyZypPR9i7scpJnV4azoO5NojNo63BmjWmjv1tXg396rUufvl6onvfc7ETjj2sQK5
         L3qJiRW2mFMahy3kvUFeXEIL69gX99rv+tbSQeqqa60EV7+xV3FmryLVORUKkPREWQfm
         CbDBTZi8D7Yu1zb2QIXQAyzRSL90Jq/IN5fPlBFQQ84nUi/1i9gdnViLaC4DbNtep4UL
         Dh/0B3hcKiE1ZdCwLbdNmRZBkYXMdwnETprs0IEGUcXu3yEMZrtrX8liYuunxcGyzaQR
         3lTeIROWCyuduzK9RqMrqs4fOceQaN/DjCxBLom54gw9ZAv4+Fj4KTa2WQO8Xv7vTk7K
         /uvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G0Hy+IfwtAkW+svX9SqfIWn/U2GPbAkpQhcppgrKBU4=;
        b=HaA15SDtCI0PfC4SK0sj0SLPFV7E0SlybpCnr1yNQkXhKbmHkxPJ0xt2OQthibZGz1
         rft0wAjS7NdnNtD+AD3CDzkW6LILAq6aVU0WfH7IuE15zHCbNtR4bm+3oSjkDSfVAdWy
         t2ShvMUoc9tbRYm3rttFwVZjwcS9Lf2Ioy7i6CU7mbCqNkQOWOYxsRFKlCbaoYF7CnK7
         Qwkm/t3aYvuHCABEAeCKH221A9+m+qy5jGHXZOOG1TutmpEzko60fWgIDLO3oVyigaZO
         T9MkoTGE4lo1iy8j5TsIVv6uWRrEsUUuGr6jYm8rYUb1+p1CkoeI0CRr+/hlfb2MPVQG
         U9cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eh1wDbOj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G0Hy+IfwtAkW+svX9SqfIWn/U2GPbAkpQhcppgrKBU4=;
        b=KAvOVtOXdqHf9fc2GpTwNk52kx1BC5yCEM1Ki8vfpBQaXvqNOaxces/XTxz0OzIZm3
         hIGDb3ldoAQ2TyDm80VFSQhq3XiUDRGmjgs24b+wZZ5PkrtJjV628LXU8PNfnvjlq5q+
         iRpMYEd2Hy9uccfpnTy9DgV/Y82ZdtB74O3lTnBYjrp4Qb1HjflH5LHKQ2bgp19XdsEh
         irPpzhfkF6ryGm4tHFhO4Wecx7qiiwHWPSyHlZvkDQKzAlLBQnJtc/IINgsgtjGj/3pI
         vdknOP1rCoVybup6X/YcjFQplHUOnaju73ZWGJvqUWpN2KoaDvZBXfyCP/cQrhcvQ6kf
         exjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G0Hy+IfwtAkW+svX9SqfIWn/U2GPbAkpQhcppgrKBU4=;
        b=HKLuwaPZP7Glr474Yxj8jjNh7j8nw2ANxE2PLasxXKVpNkBuD+LWhboLyldLVje8xw
         I2Jfx1VqaWj2TRYIjMQa4wW2wOfaNtnBtxvFmWz4Bl4dnfwV1q6troOFaEA2Ne44aaV3
         +7Eo8tKLUyLm5hEeZAN1rYrH2Tb+lDAz6umhMz3XzgN/gBK3XqogGDDL237BDD8K/hJ+
         74WZq57T6IZxx2FmTJZcMos8wnizk59QKeL2hnEgaJ29GlTV9xhJPnRmHlWglhRYdytC
         Vr2ZGPOuQT48I+X3BD0Ht+Q4dFhK6uE+OTvoz0zRK0Pxz8F4x4lTFkoOgnKW7f1hjPqT
         N8zw==
X-Gm-Message-State: AOAM533P0ew0pw69RDppz1xqQI8hj748C9FXaE+uOrsJ66E60/zp4JaV
	TOgB4cKOIw2WuO7zyT9uSBo=
X-Google-Smtp-Source: ABdhPJylsiT2PFcZJubUH0Wgcrm4tqkZkA38xmXMAgGN+T2vsVry6jpkJJao5DuT6j2mQ/tSpSg0NQ==
X-Received: by 2002:a4a:c387:: with SMTP id u7mr453835oop.89.1609876066942;
        Tue, 05 Jan 2021 11:47:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1204:: with SMTP id 4ls101114ois.6.gmail; Tue, 05 Jan
 2021 11:47:46 -0800 (PST)
X-Received: by 2002:aca:fc8d:: with SMTP id a135mr903455oii.87.1609876066624;
        Tue, 05 Jan 2021 11:47:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609876066; cv=none;
        d=google.com; s=arc-20160816;
        b=otN7GVa0X7+OwvJOyEh5SZcK5YFZSE8r7JMSBddreoXOkQiCK3DcmxXzh3FZZo/fFf
         zlfeWZjaEzSCV396dLu2hmQT7fC45N/+PGwiFqevqx+AWj+VVSg4F5UzY/6ZeQCwZZgw
         gBEILulO28J3ZbQpsXwshilO9UoxoBnf9QvXg3EbVGqeXgQzZvZq3M44EA2Wipoqt9DD
         YAqqcfrO6iLq1y+oUqMPr5yZHom83TCMjIu3aCM9NEwgLcRKmdIhthHz+M0NmSW+Gj0c
         ZWoQzBGc8EwcFGKnb/t+c7+3nE0l5hyFNUN3XwH2gcxS+7uA5XmOfgjFQIJvVBmGOzdX
         zdjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SYP7m953Sh1/b2c2QWHDIe0Jh5wcwMv/xNkLawK3758=;
        b=r/uTy7FJUoXeJ9W/fSb5+21Vy/yEOYcPzurwPscq8qPQe4Cy7USfZbN6kOQ6ypPgbT
         Yk3+R+LVIbt4DDkfzSRl1zTfUFKnR35pdnW6giVnLMfEisc11JMJ4dwnRrrMjNVrWOcs
         fqr5GGam87Fcn086dUzWPPgGcLKBvcfBWAKE8cPa1W3/ib3Prnx/O/bvp1oShBpBnAaW
         2fMrPYcM4+SPhJqAn3O9BZM0UQAe7KIX8kZNJU4qYamqnWwdoID2Kz4by20OktRGpvlh
         62CudXiuW/0yKGFhBpFvV939xq/yr2LzTpAQ0E/OqczUb+NiK6hnNyjMyxSijLPw0BjN
         7xxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eh1wDbOj;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id c18si27742oib.5.2021.01.05.11.47.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 11:47:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id a188so332309pfa.11
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 11:47:46 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr851869pgk.440.1609876065848;
 Tue, 05 Jan 2021 11:47:45 -0800 (PST)
MIME-Version: 1.0
References: <d7035335fdfe7493067fbf7d677db57807a42d5d.1606175031.git.andreyknvl@google.com>
 <X+nxQo7q2n4dGzoy@kroah.com>
In-Reply-To: <X+nxQo7q2n4dGzoy@kroah.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Jan 2021 20:47:35 +0100
Message-ID: <CAAeHK+xNDvauf-SFoBcUfcPA_6fL_FhP-w2mys+Z-heyd0-VEA@mail.gmail.com>
Subject: Re: [PATCH v5] kcov, usb: only collect coverage from
 __usb_hcd_giveback_urb in softirq
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: USB list <linux-usb@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shuah Khan <shuah@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Nazime Hande Harputluoglu <handeharput@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eh1wDbOj;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Dec 28, 2020 at 3:51 PM Greg Kroah-Hartman
<gregkh@linuxfoundation.org> wrote:
>
> On Tue, Nov 24, 2020 at 12:47:25AM +0100, Andrey Konovalov wrote:
> > Currently there's a kcov remote coverage collection section in
> > __usb_hcd_giveback_urb(). Initially that section was added based on the
> > assumption that usb_hcd_giveback_urb() can only be called in interrupt
> > context as indicated by a comment before it. This is what happens when
> > syzkaller is fuzzing the USB stack via the dummy_hcd driver.
> >
> > As it turns out, it's actually valid to call usb_hcd_giveback_urb() in task
> > context, provided that the caller turned off the interrupts; USB/IP does
> > exactly that. This can lead to a nested KCOV remote coverage collection
> > sections both trying to collect coverage in task context. This isn't
> > supported by kcov, and leads to a WARNING.
> >
> > Change __usb_hcd_giveback_urb() to only call kcov_remote_*() callbacks
> > when it's being executed in a softirq. To avoid calling
> > in_serving_softirq() directly in the driver code, add a couple of new kcov
> > wrappers.
> >
> > As the result of this change, the coverage from USB/IP related
> > usb_hcd_giveback_urb() calls won't be collected, but the WARNING is fixed.
> >
> > A potential future improvement would be to support nested remote coverage
> > collection sections, but this patch doesn't address that.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Acked-by: Marco Elver <elver@google.com>
> > ---
> >
> > Changes in v5:
> > - Don't call in_serving_softirq() in USB driver code directly, do that
> >   via kcov wrappers.
>
> Does not apply to 5.11-rc1 :(

Hm, I see version 4 in 5.11-rc1. Let me send a fix up.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxNDvauf-SFoBcUfcPA_6fL_FhP-w2mys%2BZ-heyd0-VEA%40mail.gmail.com.
