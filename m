Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBQMC4GAAMGQEPLGCMEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B969A30AE96
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 18:58:26 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id q11sf7950158ild.22
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 09:58:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612202305; cv=pass;
        d=google.com; s=arc-20160816;
        b=F6sDM3WoGi5Zs2Dd8Gr+Z30rb3uj9zJdSCiWDvO2GJMVvF8y5EMDVaYYlaGeMLVIWS
         yL2zESPp3tze1E9Hy1Pm2rr+y8d0qDCyqg2REJYa2E/Ph+nzfeC4KJwFUD5V6qTTO2+n
         h74VjcLKYJFHW9n34B6dZmdqwb+RBSwGItFFO2u7eOigPjmSH47XqPReLkW6Yhs/8sVM
         lL4r8AkIIxAEwbGeSDiNtOzHaZVEqs0ip01D7VF2Y57vEZ7Xv2Mn9IjhEK5Lh/Dgj/rH
         1Cdl/nzn+tnUMdSZAlQB5IhATjqL6XSTDq0SMSqenSLQshRlAZNIVYgjCX/4Wez4LRhv
         37KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=acYT0/99irSNCjz0KX9XCBqyb31MQY/HPZbeIE5yaeQ=;
        b=O6gu4Vi6A9MlSDwbH1c3zhlexEvfuj33UVtxB17RUwxr9zcblJn7JRi6t/LXTtmYW5
         e6XtmERfWQvpjT5sMC+Cxy7zCgBLWZSzIUfX0KWeknz4RaZA+Z6EwYAbvPK4LuzhE5xI
         Noyui5wshrIRalLBKOoBpY0RS1wmKTIRdZshU4u5KcD/4NRbEMPy+9HXGH22CBe2Gp/V
         0CEbqYbh0hwoBmfYV0Q7YUviI96cAuQuKo2VlegEdM9Sv0oP8T7CW/kI6B0NVsRB3fVC
         pJYuOeivtmRbpxXOf4QNkxB4VMjBMZq+ClKr0yYrSq1I0uNuU4Q/BjMIY3KWlfL/isBs
         zOhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=klKDnUEL;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=acYT0/99irSNCjz0KX9XCBqyb31MQY/HPZbeIE5yaeQ=;
        b=SBDsZT3zjrm8LwTxuaxf9lXfmvTVcxakC5+b8fW5lsUMPIpAVWmtwGEPPvHq3GO1AP
         XCbctn8PXZ/nzF9IeAx+yhWFy7GFNwt+zCQN/rF4CCOTIzTbfe6xGbZCzL5Z6sER2x1a
         pt1IEASoTqH1WFIYHUqo5D/tiIWtvh6LIcvIFqIvTkW+T8w3DaZdDM2DhOBIf4rjdazv
         utDuDkbu4JxH1RWldaDHxNovryki65PI/AyfB4tmGKDVSayABk6wNzwMQ0Xcq32nNpdA
         dL3HPC1MIrXNYJ26RSi3Q3lxBAZli5GdioIXFVd0rWond+MdWTAfpCle9o+utcwHnhDO
         ZVcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=acYT0/99irSNCjz0KX9XCBqyb31MQY/HPZbeIE5yaeQ=;
        b=aC5xbLfhE/mSjN/hcaGYMKiQvZ1tV7BAoYcyekeDITOn5OARQY8sd5u3z6PHHwuRDr
         VHc5ae8uVZkc1abujC8pUqohL82+UGxGqABmb+n06/1tAwhqE/uyQQRIN5vgtKbqgEqt
         1LjFgySeJ8ubZTaT5VBIshXuY81kE8BC2XVmQJCflO5KNFDyJsZ1t3lhnghffBFlaem0
         6wRRrIlH2SYPXL1jiykX48AxQbYUWzMYtKxq9fZmNSZ8PhsQyNDINW0nwNTjJbHd0ozh
         pA8y4b/rFfvezzoGRk5EDFNzHj2NNUR7j73PO0LY9Y8ixkZrEsr0QkmF7xkor3MSpCaw
         q0Kg==
X-Gm-Message-State: AOAM5319FnxM9fEHI27YnH61yktEduPhK/nihsz12VuKf20DIJNaHlrj
	1gjMcPJiS96o8QAf3R3dHBs=
X-Google-Smtp-Source: ABdhPJwpMMWAhgdqtxW89QsF6VQnRgedrOWQpVK8ybKWvpTsg5+goUNznDL33yVSLkn/F8+htbXCGg==
X-Received: by 2002:a92:bd06:: with SMTP id c6mr15343315ile.158.1612202305758;
        Mon, 01 Feb 2021 09:58:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6d04:: with SMTP id m4ls2079494jac.9.gmail; Mon, 01 Feb
 2021 09:58:25 -0800 (PST)
X-Received: by 2002:a02:ec5:: with SMTP id 188mr15823699jae.20.1612202305271;
        Mon, 01 Feb 2021 09:58:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612202305; cv=none;
        d=google.com; s=arc-20160816;
        b=UNTLigbByBhWVPNn913VUdV9UyF0cv+SydY9kVpkwK4a5EYfnx84CQBcuzMQPbaMBY
         DbtoNgRCgrEZTvDSYOFyo9PvZksNdZXcmIK1vN3H6lhtqtpiA0BRYzgzi6N/MV3sgZ/l
         2xpdXFJj9GqKof2cLcmO5heMiqgQCbRP2yEnjg5J2f5sn2NAtFmvKZfsD191S6NkDjEb
         q7FwrGpDQylr7C7kqRZ09fpeeDOo1+prBwDL4L/AbwaMXedrixTqgsshV9jTv0L3NUET
         ZulQXWqRT5ttYaZ0I6SoheHoFNM/dzr+zGoh04bBXB2HOvkkOcBvyLcvqzhgY7Ke9Djt
         CoGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bv8ZgkdpbtWRz3CeKeqPHjo/hOCKsBVIEdmTNlxLJSM=;
        b=cyl1/dUQ32b8i7eLW73xLQjiwEgdGyDHOv8oD76CBAXg1FOTP4jO+8xmjQRjRuhp/8
         Q6+uF+er6Ra3UBOAHjeZbRuJ15M4NM13w0YUvo7vgDS1s4EXXTAyD9xjTd9exOblL+el
         UoekCx8ERa7uDQMzVD9zLhGZSUxujNSAV5kFp6f9SfoLPMTRSitq0H0DXn1d3pzKIvQz
         vgvDn1Qx8nFSpIFFN2K6yO0L5PY5M0QvfJLr2j72tJ0mEdaUMAA7ZjbRYqeCvNpdrybO
         uZdYFv/HE7MKbuFhz1YaQXJQ1LEJ+617jg3xEqSQTnieyZxy/vbPDP1gdy8fqWqJTTPk
         v2RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=klKDnUEL;
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id d13si690615iow.0.2021.02.01.09.58.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 09:58:25 -0800 (PST)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id y19so18356168iov.2
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 09:58:25 -0800 (PST)
X-Received: by 2002:a02:e87:: with SMTP id 129mr15622009jae.34.1612202304740;
 Mon, 01 Feb 2021 09:58:24 -0800 (PST)
MIME-Version: 1.0
References: <20210201160420.2826895-1-elver@google.com> <CALMXkpYaEEv6u1oY3cFSznWsGCeiFRxRJRDS0j+gZxAc8VESZg@mail.gmail.com>
 <CANpmjNNbK=99yjoWFOmPGHM8BH7U44v9qAyo6ZbC+Vap58iPPQ@mail.gmail.com>
In-Reply-To: <CANpmjNNbK=99yjoWFOmPGHM8BH7U44v9qAyo6ZbC+Vap58iPPQ@mail.gmail.com>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Feb 2021 18:58:12 +0100
Message-ID: <CANn89iJbAQU7U61RD2pyZfcXah0P5huqK3W92OEP513pqGT_wA@mail.gmail.com>
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
To: Marco Elver <elver@google.com>
Cc: Christoph Paasch <christoph.paasch@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, David Miller <davem@davemloft.net>, 
	Jakub Kicinski <kuba@kernel.org>, Jonathan Lemon <jonathan.lemon@gmail.com>, 
	Willem de Bruijn <willemb@google.com>, linmiaohe <linmiaohe@huawei.com>, 
	Guillaume Nault <gnault@redhat.com>, Dongseok Yi <dseok.yi@samsung.com>, 
	Yadu Kishore <kyk.segfault@gmail.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	netdev <netdev@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	syzbot <syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=klKDnUEL;       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::d32
 as permitted sender) smtp.mailfrom=edumazet@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Eric Dumazet <edumazet@google.com>
Reply-To: Eric Dumazet <edumazet@google.com>
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

On Mon, Feb 1, 2021 at 6:34 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 1 Feb 2021 at 17:50, Christoph Paasch

> > just a few days ago we found out that this also fixes a syzkaller
> > issue on MPTCP (https://github.com/multipath-tcp/mptcp_net-next/issues/136).
> > I confirmed that this patch fixes the issue for us as well:
> >
> > Tested-by: Christoph Paasch <christoph.paasch@gmail.com>
>
> That's interesting, because according to your config you did not have
> KFENCE enabled. Although it's hard to say what exactly caused the
> truesize mismatch in your case, because it clearly can't be KFENCE
> that caused ksize(kmalloc(S))!=ksize(kmalloc(S)) for you.

Indeed, this seems strange. This might be a different issue.

Maybe S != S ;)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANn89iJbAQU7U61RD2pyZfcXah0P5huqK3W92OEP513pqGT_wA%40mail.gmail.com.
