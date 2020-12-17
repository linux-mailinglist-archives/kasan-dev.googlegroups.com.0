Return-Path: <kasan-dev+bncBD4PXQHMQMPRBBEM577AKGQEMLGI3PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CEE8D2DDA66
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 21:56:37 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id l23sf239536oii.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 12:56:37 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+kDcRrxgEgX8DkbxaQtkT2MyfobP/A0M77RtNXb3kXU=;
        b=lGyYBNCvdUEdR0mCe6Hu47DwXey/F4CcFi5wWtBF5OQCpWJfcD1noouzXIdcd0iH3L
         nAc5W4sbze3ZEFUb5H/GS9mzXIbD+Pk3jg8OUB87/TjOpPJy4qfYSe+L4kSuaOmoXgk6
         P+PysOrw6hr0GPrN+zPP0SqKQJfyqFAPLQfV6YMoBSBmD1H323iA/Wbu3g+yRet4DXoS
         z0USL96H3sEf5Rb3+NfwpYgDff/OUSFQp4qBzsAKLKHrLJMIFE+XiOEf17M5QWbGF1OY
         7TPAUMmkCkNQOtyoI0Tm9nnoZVzxNkGblCOQcSI6js1+fX2aZDecrnNbY7F0fwqthE2g
         5szQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+kDcRrxgEgX8DkbxaQtkT2MyfobP/A0M77RtNXb3kXU=;
        b=ThllU0yaTXOVmQQBDAa3kFnZ5Ji9NU9qnkELCSZKoTPGe/22JescZHxPdtREmJiY9o
         6asz5hdujOVYVEqtQ+XfHH64x7iJWPBb/Ya/rihSfNP/neJ1xYipqETfe8J4wD/I0lPd
         kBp7c1e3GoXzvqUecp6l350RHadoP/DWtXt3z3Z13zLMs8UDv5wbG/qy682DyCTgHEE3
         kMT+W7D3YxdlejP65z4ltmRediRaSGAN1P4Tk2i4uIk+c9I7yx6YjnlnTomW9axglof/
         QDWoLuQmHV9RwIhdTljMiyfH49Kfq8vXaBKfglEtsm7UuoR8qeVRXhnOPyXW3JALXyQ6
         se6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+kDcRrxgEgX8DkbxaQtkT2MyfobP/A0M77RtNXb3kXU=;
        b=MJEmLqwFwbyx6yJb5Zvx0GKY1k6XyGP2yD4Q94rGfR19XmHdv9fjArSPUYy/HHX2uF
         Fvby1WvnDvwpZfQpld6whFre1tdTrMesoS7hyDpzyNDQLoypLz7PtzmFI7rjPGUhXy/Z
         YioQLsYli/AYjC3TmjQGs32z+jSKrQpA8EsUcM63W2ARBgClu2MO9I//iFHsl3ZYwzdi
         pAoQdPmwKmGfk8XqTIxvgyQ9LjAGn/vpzQ4SvUTdNTz46M+f2qjN6MmLgh0Xm7PtPcgx
         MQippgPbjtHmuJCle1Eze49hB82a00qzc7x8j9K12xGKgf4AFqZsrqY6RBuF6KZansib
         ovSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DSpn9ycOX5vgFdvRlG7xMnIUfReUKmKUniROgv0MPlI+vHomj
	OkF85shqFcIQdwaVmp/pDdY=
X-Google-Smtp-Source: ABdhPJziv1MIw3E5PSXD1fy+6eVUxbw2PtXV0OhAwZJ6egJLQMWp+1xXnaUtmRLayeaWawivjhExSw==
X-Received: by 2002:a05:6808:148:: with SMTP id h8mr767729oie.10.1608238596879;
        Thu, 17 Dec 2020 12:56:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c413:: with SMTP id u19ls7165815oif.11.gmail; Thu, 17
 Dec 2020 12:56:36 -0800 (PST)
X-Received: by 2002:aca:30ce:: with SMTP id w197mr745287oiw.29.1608238596463;
        Thu, 17 Dec 2020 12:56:36 -0800 (PST)
Date: Thu, 17 Dec 2020 12:56:35 -0800 (PST)
From: =?UTF-8?B?16LXqNefINec15XXmdef?= <exx8eran@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <10b4ec66-1552-4224-810a-81ac2cb8d097n@googlegroups.com>
Subject: it's unclear how to activate kasan
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_4626_1138331348.1608238595553"
X-Original-Sender: exx8eran@gmail.com
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

------=_Part_4626_1138331348.1608238595553
Content-Type: multipart/alternative; 
	boundary="----=_Part_4627_1700536259.1608238595553"

------=_Part_4627_1700536259.1608238595553
Content-Type: text/plain; charset="UTF-8"

Hello,
I would like to start using kasan.
In the guide which is attached to the project, it says the one should 
CONFIG_KASAN=y
I don't understand where and how to set it.
If anyone can help, I will be grateful.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10b4ec66-1552-4224-810a-81ac2cb8d097n%40googlegroups.com.

------=_Part_4627_1700536259.1608238595553
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello,<div>I would like to start using kasan.</div><div>In the guide which =
is attached to the project, it says the one should&nbsp;</div><div>CONFIG_K=
ASAN=3Dy<br></div><div>I don't understand where and how to set it.</div><di=
v>If anyone can help, I will be grateful.</div><div><br></div><div>Thanks</=
div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/10b4ec66-1552-4224-810a-81ac2cb8d097n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/10b4ec66-1552-4224-810a-81ac2cb8d097n%40googlegroups.com</a>.<b=
r />

------=_Part_4627_1700536259.1608238595553--

------=_Part_4626_1138331348.1608238595553--
