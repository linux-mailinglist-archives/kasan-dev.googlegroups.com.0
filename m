Return-Path: <kasan-dev+bncBC37P2UJRUBBBWGLRDZQKGQE2XIE6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB1B17BA2E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 11:28:40 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id b23sf714538wmj.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 02:28:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583490520; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5RxhcASjXQMhOpV84A5oLPu7LvSmycH24GYOHRegwpYP5hfKE5njZQqRLsHgxcp7y
         kYAUJz3tPdWc79/Jnh5jlGvIGZ24XlJS9djTkVO0nL/CkuL0CfLOCR2WdO8uhkzvFoyu
         FJ7JLJ6EtHVKUxfxoqIQUIeFG/tyyx8fF/MsUfNqP9O7yl2UKS/k42kSjWniLaALFms9
         nJFSVFC9lagdX2GTxEityBZmJYyUA//aRMMcz3mN39PMpRe/8Ttm81OKG/JroOsmlQjo
         3W4IZn/etLwNvtu+uD7ni7jOxrLZn7/A7/jg/dgI2MwwBMdoQ2YllbtG6BaoesN/b6es
         Y3Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Bf/4a7z+/Dk268vR8aS3MoH6oLkeUBjMlbbNelaavMw=;
        b=srMVdndmJdqkM/97GuLfHXz+8yXhAIVmANvx7r7KEGYjLpe7pD2sVGf6HLo696FIb0
         Ts1ZrvD2blZC1lQljoHKCOt7AKV1NcfDYL5nd9QKs9VW/xyKSCr4MNaaRekULttAFypQ
         osZRcabmVyIVEGNlbUkBIqmjnhpfcQ5L7lyhn0L8mCEwM/dCwFFkD/jYM5jpvtOoTmgt
         qcLK0TJ8S/EbKh8AfD2NAWTpDNouh49rruhckLMbbZ98lgy68daky5RqCQ3Q9+/X158W
         Yp9gup9G2szyr7csWXV6znei0M1IN37eFQvRWj1si0TbzQxJEymi5LVZCOC/iDR/D+4p
         IGXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OMast6sG;
       spf=pass (google.com: domain of majek04@gmail.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=majek04@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bf/4a7z+/Dk268vR8aS3MoH6oLkeUBjMlbbNelaavMw=;
        b=hoGjyMAf95ioiIZWQ8SnqHtFCcKu9ur7IqTz8ViYCKDXef1cHnp2+pp8bc6zbN7Tbl
         rj6T0X9omFj69+WIjf1HkXcEA6oiG3AgzBfjs6gtvZyWu8wJ6LGIMob22JlT6MdI8X4x
         tMMDy6zwTMa5Pi1XCeZGs/6CpAZE0TsMaQZbAq3NjmxqGQMLh74wiHZtJiJWE20s1CNl
         z3gcX1/tKabTfwqwi8vteGxUK/hckDqlrfXh0SZ9j+6XP4NvNHa2ZxdtGk/FabZ9EE7Z
         MMl4FFMtqjiuyr7J629cEw11IyVf+4PFS7ERq8x64UGa5McZUhYzMYWFn8LWrKxtFukH
         AMjg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bf/4a7z+/Dk268vR8aS3MoH6oLkeUBjMlbbNelaavMw=;
        b=WahWSLz6LBa011tnCGKjpOICSf9pp7OQyQG9XvgGo9/9VeTLcA1KcgoAhQ59TOS52K
         pPtc8CzSLUkOLxFmbOjhX59hIXslkrl75XO9GydK8PZG+RtXKej641f5f7t8/6eVN3eu
         1Fxhj781teoJpJkk0g7fCezSG1zG7mXtZhY5D82epFQqjKOuFzWw2p0SamSwXyqHF8Qc
         aEHjpOowJxYKIeawUBQQI/9ecTDMjhTanBqm4HvNUSvPs2O8CcYHrci1C0LZy5J2Hi69
         xjj3+wuQrjNP/w5AuHUUlLX5fW1Pzx+yj6K9ZgrKxCCUM3iro/QdCGWWIOieHiagJUx7
         6hsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bf/4a7z+/Dk268vR8aS3MoH6oLkeUBjMlbbNelaavMw=;
        b=gOUyzPnWyl6yhuVjy0OzIAV7hpP5Txlhf+5DNJ+wVSGMKEXg3PxJj0XmIrakgqkLkp
         ZRVYP9Q8MU7cNVVDXXWm75zUcC7dWxH+XB55kAe8EIevRWo43jg038c5BMs+Avy314EQ
         wmxo8aeOB6gefbxrvcOLRvKVnSb44tOv/utJoSvZGvXKGDAW/Ai9Fef033JFLZrshm+p
         aaKIokOfmq1AzgiOBDFeZx71W8BjGsG9L4Z3Xn2/TLRPvHdaSDN9qGbx+RFdIGtwMXPL
         3k8iFauMeFzTR4igD+ThS9QSqQ/5xUEil0FOjr02tGP4Pd/X4QJHI3+0DW36Zj8fSJDd
         wbvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2BmUP9S7+XuLTRDm0LvM6jdcuDBKSE9XAcd54kRWo+s9Rio30/
	U9/lvHr9ibPtyyDN88xw92M=
X-Google-Smtp-Source: ADFU+vvZQ7A9dCtmggHLaWl1h9fLX+bpTuHqvLAzA6bCTB5VjoF24tlWf+TC57Ef61sygKamK3kB6Q==
X-Received: by 2002:a5d:49c5:: with SMTP id t5mr3392022wrs.154.1583490520608;
        Fri, 06 Mar 2020 02:28:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5710:: with SMTP id a16ls820143wrv.5.gmail; Fri, 06 Mar
 2020 02:28:40 -0800 (PST)
X-Received: by 2002:adf:f588:: with SMTP id f8mr3501102wro.188.1583490520067;
        Fri, 06 Mar 2020 02:28:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583490520; cv=none;
        d=google.com; s=arc-20160816;
        b=jo52V+orEjMT/m4KwQKsAWmACoPFr8mt7r8oG7NwVCX4adTdy9YVBr6a8sRGQSNLGn
         RU4qV87btEFDeAzD0ypQq1VHsph7m2EJRopzc1M6xURXNe9cH9GPe4pNxi0i2FoMseyh
         PxHllybSpsxtq2WPCE7VTuqlyLzoumaHNI+gPrF2lwWh1/im5e7jq5oHLC+4JpMg/n//
         WoPvHA4UwDM13am3pfnNyTULmFC5kB2Vvu7SI5OQ2SsPVLyTkQfPzM6xVSeQTMZ0OXz1
         Yp/HD1beVDieeeAxR7QayZKk7BkHxY+f6yWNk3nWPB3KGtJYqVT9OT1oZP5dwCkf1NA/
         JbWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b4ytCPY3IE1vNiZQnIO2risY4Q6hHJIaEm5BHM54WJs=;
        b=BNNq/lCuJx1UcmYPGxzg7N3sSIzZlLQkeLQm5jFM+DzlWO3Ul9upccVMv9tnBcXqPX
         H/7+F7chtn8z0MmbjXWnKZQdroruUVA7kFJ+Lp+16/wRQd4Rjzx6wyCEoI5NLrggv4MR
         RWd9zFqtASnDm8e3d4Jgh8aDD0b/Wks8alz63FRBQDqCWgBo8b5IgUqpATmWOkZG8GxO
         y4JRPmCUNwTqcO9QM9/qmrdRmrq8lzQ14lJd6lcdY1qzGXVn1C4AmgkswRnNMyQaIfTG
         o8CMqmlpg8MwANbjVj5krbJEM3+r+eGSh9cSLt2A6NNDc1hgX/SPAwL+pXshSA9dBjo6
         ocdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OMast6sG;
       spf=pass (google.com: domain of majek04@gmail.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=majek04@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id w20si637538wmk.0.2020.03.06.02.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 02:28:40 -0800 (PST)
Received-SPF: pass (google.com: domain of majek04@gmail.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id a10so1625193ljp.11
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 02:28:40 -0800 (PST)
X-Received: by 2002:a2e:99cc:: with SMTP id l12mr1547504ljj.271.1583490519811;
 Fri, 06 Mar 2020 02:28:39 -0800 (PST)
MIME-Version: 1.0
References: <07a7e3d0-e520-4660-887e-c7662354fadf@googlegroups.com>
 <CACT4Y+aanRYNL6N0M7QxftmBcLQi44MenZ+oOUap8g9AtvzZvA@mail.gmail.com> <CACT4Y+YnNXpCCfQXr_BhwKZdEFKoS_7M1AZXaxmi59iA+VFH2A@mail.gmail.com>
In-Reply-To: <CACT4Y+YnNXpCCfQXr_BhwKZdEFKoS_7M1AZXaxmi59iA+VFH2A@mail.gmail.com>
From: Marek Majkowski <majek04@gmail.com>
Date: Fri, 6 Mar 2020 10:28:28 +0000
Message-ID: <CABzX+qxqzaHjinb21GNgzOO8B=HNEZ+fRpjU6LD68dF3UTZGsw@mail.gmail.com>
Subject: Re: Kasan for user-mode linux
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: majek04@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=OMast6sG;       spf=pass
 (google.com: domain of majek04@gmail.com designates 2a00:1450:4864:20::22e as
 permitted sender) smtp.mailfrom=majek04@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Mar 6, 2020 at 8:45 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> FTR KASAN support for UML is being added:
> https://groups.google.com/forum/#!searchin/kasan-dev/uml|sort:date/kasan-dev/55i8KM62aSY/_SNEkoRfAgAJ
> Marek, if you are still interested, you may give the patch a try.

This is great. I'm busy with other things at the moment but I'm
excited to see this being worked on.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABzX%2BqxqzaHjinb21GNgzOO8B%3DHNEZ%2BfRpjU6LD68dF3UTZGsw%40mail.gmail.com.
