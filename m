Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPXNUXVAKGQEO4WSDGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C288C831B6
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Aug 2019 14:46:55 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d6sf48233269pls.17
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 05:46:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565095614; cv=pass;
        d=google.com; s=arc-20160816;
        b=pVyTuQ37/TVzBesyvvRMFkCS32O8vjdC5hGnmGJuf02EvKdfBO2rolPLiGt/hG6Kcm
         ChXUUarcFCig5dzPtbFrnl/NvJ5g6zpnx1PlFo0g+rNY3iLxrwH7eykFLh6g/Aasc2SP
         lbjZR7uoAd2plKLwZpyjbs8GMdkexbzDJQi2q50rkqdREpQ82TOPL2beuLOKBepT6jLN
         svMGKImcoYA/UosmC45BgKcPCESyPF7NQhnKQCVt+GrNinSzMsP/5W+JtsQa7f2nb4ih
         cGuTUXW4u+r48UCPHdb8YCzAyDsMQVzhGkhRpPTYdUzR3HB7OZXN3eNLXTO60E/R5qJn
         4TKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ay2vUhcK/QLei69s0MbjMxn/m5cfRk/TByb7PvJ6OR4=;
        b=xPlqW0zKeQNiajhFLgJIxDvHVkWoMmYjJnk93tDOlMCc2oK1ZCf5khp+zZgoWBIHwu
         n4nJ1234I1N1tTvCEcucaoQMhgqMQH3FiXpej0eq9H3Ew73ag4sOTl2V/mZvklF+x0Cz
         VICqdnoahlKMQnPVZvXkuc61fLHL+LmIUXypY6kVmNEAXypN02XOV7Z6PVJyWQVyaEmJ
         MxU+ibGMrjPpyXpCnxnPGtK4Lml2vCWGVpiKVel6vjYzyb4FvHmQxM+aTijllXXpnpXy
         0DPg7OBjKiSW/J+eZyPIPnuraJ9TrH/VxE8pyrxxCeWHLAtY+ulw2RM2my2pPHom86sT
         EqRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YxWuhVVP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ay2vUhcK/QLei69s0MbjMxn/m5cfRk/TByb7PvJ6OR4=;
        b=B1ocwv2m4Q5y/8F1TLIL7CMyIaIPX6AFDsx09DfsOnrJYgW8HcbKLOw0V7yOWruwBc
         kje//bKL9SQ0Nn7meMml1RkBcN79AcCDQ+gkugA+oxCVsNKx5eWYEfRkYYu3YS2uo8wx
         iItm1RUhQUFHdaj5s+DixBoQn+UwgX1zHsiAXvJnazUhj71TQ1jsBub3HN2evFGZ5h0A
         gw4zAGdaguJt3xmJlbb/YKfgLxYlPQynavw8dpwK7+Xmg9EZitOCqtXMHl5LqWG3RtrQ
         DOXkPq0IVVGT2v+hyHxEN/UGsNNl3p5zrFzvO4USpOBrPigon3n/8vyjVCEZGFfZk662
         88hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ay2vUhcK/QLei69s0MbjMxn/m5cfRk/TByb7PvJ6OR4=;
        b=do1HONqEb0YoHC3gWh5qTnlvo60R5lIHNMOIVRdMeKUD++XME2sqNc37gzzgRkSksI
         Q0ghCcsbycI/7lqjd2/Ua1MtUpU0/AAbNbW6K2wlGZ/QmrUICsmQ6W+CMw+w+k9W+nZ+
         sdGJ0Vk3Q3lxjX2lt6AT4w85Kz3BCN2ZSuhlmx1pjqmpuDogNqFlFEjAMPPM7M4gYoZp
         NQtikr96dSO0XO4faLxul+X39URcRww7igAp1Sv4/fORwGHML5C2I8bbyzrzQNpIsKTQ
         YztJ7l8hj/EcfhyLZR0iQFppKlZOBTZ+/0pOJT5lNLuG6SvISGFqW+p6iJ6d9aUcBhU+
         Ncxg==
X-Gm-Message-State: APjAAAWKQ24ANfDmFu338NKfd5JQhMDM90jWRt9yib99ViRBQykvhEoz
	OrlwPTKD7C86dq4zK+FraPc=
X-Google-Smtp-Source: APXvYqzb+UBzuUVXy7Q8QEG1bjnpa7yAC6y6B7vwGtfPVDXRVCO5NkHbimKimlhwGsgCB2KHvjGndg==
X-Received: by 2002:a17:90a:2305:: with SMTP id f5mr3205695pje.128.1565095614242;
        Tue, 06 Aug 2019 05:46:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:47ca:: with SMTP id f10ls6779097pgs.13.gmail; Tue, 06
 Aug 2019 05:46:53 -0700 (PDT)
X-Received: by 2002:a65:6081:: with SMTP id t1mr2948943pgu.9.1565095613806;
        Tue, 06 Aug 2019 05:46:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565095613; cv=none;
        d=google.com; s=arc-20160816;
        b=kW3R4+kIUuJkOJLqV+LNL9fDtSUZ/eP8/rTY023uOwqeAqWtc1HjL5Cj0RFlOYRWAc
         QA62JNgozERRy1kA9VcWHZoPPQOenALsCBIHaMA7UgJQUDxQn+r09CeJAUFAdMJl+DJL
         Ob5MvtPQZ7FOwdW4oZc519rKSamJdVfLrVW+Xp1UYW75rO5G2JOnea2DC612BL70w/Kn
         9mQfkeNdZjKfQHj9uwQe531ymg0N4Puwx3dbZyxrhPpDw+Mewe88+P53zp9BcY0neUbl
         ayYck7vbxcNBrGnjAnFhyHc0IF52lD7qtS3TcGn1lH9qkBWx53H51B4tiAPHKGB+7ovl
         qOCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OhYpeipAM1cJGk0zRufUu2W1ATcxkpvyxvScspZ2YDU=;
        b=i3XQuT7+NFo9ebWUMRB7ckONlmy2Naizd8kMX3iQUrOxtUtk/ib6JfDczTl9ZAzVWJ
         uTb3VcheQDZsEKwETU20aGjELAYQ0dgQzWjXshcXN+e76AultBs7RFpoO/qlWwEl9GzS
         /Y7Xkcolmv2RAZOrk9E2WolwaL+0OrjHNcl4Ye3U2brQm4O8BGHb2yNKWHl97P2r4r98
         w9QEg7CFJbX9gb7aGQesSGfMRL65Cy5QO2JFMpiTuK/RQvlTOEqxrAhZPoq1VzWuJxtl
         0R/ZI3uTpNeGnG/nUXElyAx2C94wR5/2KfGTn6jkTPTE3yL4FsSZABjI8bsiFLkRxES1
         XZ1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YxWuhVVP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id q2si3043254pgq.3.2019.08.06.05.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Aug 2019 05:46:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id n9so35327861pgc.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2019 05:46:53 -0700 (PDT)
X-Received: by 2002:a17:90a:2488:: with SMTP id i8mr2976904pje.123.1565095613100;
 Tue, 06 Aug 2019 05:46:53 -0700 (PDT)
MIME-Version: 1.0
References: <96b2546a-3540-4c08-9817-0468c3146fab@googlegroups.com>
 <CAAeHK+wp7BduMoNQEOLgwB28pYLoKrp=cHiAzRW1ysu27UBn2A@mail.gmail.com> <CADVap6u4DtVVr5SRw6Qw=GZDWvuVO3wTLDzFdC+P-m4pGYBjBA@mail.gmail.com>
In-Reply-To: <CADVap6u4DtVVr5SRw6Qw=GZDWvuVO3wTLDzFdC+P-m4pGYBjBA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Aug 2019 14:46:42 +0200
Message-ID: <CAAeHK+wLm4e5mzbVzOiz6c+SiXFwZUJPFesgn2GjkJmUO=uhCg@mail.gmail.com>
Subject: Re: I'm trying to build kasan for pixel 2 xl ( PQ3A.190705.001 ), But
 touch is not working.
To: sai manikanta <manikantavstk@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YxWuhVVP;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530
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

On Tue, Aug 6, 2019 at 6:50 AM sai manikanta <manikantavstk@gmail.com> wrote:
>
> Hi Andrey,
>
> Thanks for the reply. I have 2 qsns:
> 1. What is the driver for pixel 2 xl or if you don't know, can you tell us how to find it?

Look for .ko files. I remember something about having to run "fastboot
flashall" to flash driver modules, instead of some other fastboot
command, but I don't remember exactly and can't find any references to
what I did.

> 2. The touch screen isn't working, so I was unable to do "adb shell" due to unable to set VENDOR KEYS as touch is not working.
>
> On Mon, Aug 5, 2019 at 5:04 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>>
>> Most likely the issue is caused by a mismatching touchscreen driver
>> module. You need to flash/copy a KASAN-built one to the device as
>> well. I don't know any details on how to do it though.
>>
>> On Mon, Aug 5, 2019 at 1:22 PM <manikantavstk@gmail.com> wrote:
>> >
>> > Without kasan same build works fine. But after enabling kasan, compilation is successful but after flashing the images device touchscreen is not working.
>> >
>> > Applied this patch:
>> >
>> > +CONFIG_INPUT_TOUCHSCREEN=y
>> > +CONFIG_LGE_TOUCH_CORE=y
>> > +CONFIG_LGE_TOUCH_LGSIC_SW49408=m
>> > +CONFIG_TOUCHSCREEN_FTM4=y
>> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_HTC=y
>> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC=y
>> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_HTC=y
>> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_HTC=y
>> >
>> > Still no luck and touch isn't working.
>> > Can you provide any patch/ any inputs to resolve this touch problem?
>> >
>> > --
>> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwLm4e5mzbVzOiz6c%2BSiXFwZUJPFesgn2GjkJmUO%3DuhCg%40mail.gmail.com.
