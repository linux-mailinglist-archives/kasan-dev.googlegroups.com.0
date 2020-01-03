Return-Path: <kasan-dev+bncBDPNRNUM4INBBRWDX3YAKGQEXBP3KJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C51D312FD87
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jan 2020 21:19:19 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id o5sf18205855oif.9
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jan 2020 12:19:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578082758; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVQf8bWGsJRH/a7mjeoxMrFFY5Xef3ZovqIg/iq1X8i8FnhtlPWUghIOcLJ568t+f0
         fB2QUp2+lN/3hyFAAqLb86UMOxW+Dp2n6FPEOk+0DPtMp+T4rxH7h1wxgn18uOwfyGqn
         1JoqSQ/zkmndFHaPSZTdQFviJW2Rd2dV+V9OuopAe48FO895SXelSaA1+UjL63S2Byvu
         Uv0XiR2Gm+D6qwxnQgTiAnTeajSNTmVKs1vXkF7bM6AibARoVrWbVHSsCvx3ME31JSTH
         y1mnoptgslM8A+UT5qB0cVYvgIz/xo/a4dFHo3wuU4SqC8i2w8kuSq/1NYaW6543aG/C
         5uGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=PGV9hCcukbJXdjwikIPJCCJ7y0lm9gzp/mhGfIgz/V0=;
        b=Ya7l5K5jqECBYy/m8/vPVb4dAXaQJxJaXL3Y14diOPPkyiq9z4Tmf7CGpR5rsDfegg
         ed7flyUV7UkfnU3NFet+9dVDJufCvt9t6u3lu9NVI3/uI7mcovAnYnMT95NJi280kF0g
         pokr+B6cc4IHIIyj1teiK1EaW/08xcViprucBjsocpJuPFBR6f+iQOp6jgQcnw/xIXmB
         T9bskwrilYwH9HAJSZ19c0Ec8muAVjL+sZ5xb4IDrFCi2wlg9O2zrIZGeYW9xpOm3SXb
         elufNUqwcJrSO39hGyPKCfWHuXwY5qljj9GhWKCr2OwxkJyGmyyyJYFOklILOux6kYNb
         bYqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eVI94djE;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PGV9hCcukbJXdjwikIPJCCJ7y0lm9gzp/mhGfIgz/V0=;
        b=Rn8zEBbwBJe/xw8bO7sbwxvqSlBKBUhK+2ehCK+tuxMDoFkwjiNyPPWIs+KIkS0Cb2
         ZanEnzstmZF3OTtPdqygEJjkSBMtTHWI7lNUUxc5mNepww2poOiNevVBk0z3RAQUqlxR
         ltyZIVusSDX08lNqXGOG5rd6tYPeG6u6qXuoIq0YGLCdKBVUb0J5NVGKwswNdCzGPr/R
         yJYyWUxNv4zUWLoarTDGdjBlQx4aFmxQ8NYUbdDDwNUJB1p52Cq9zX7I8AkeQ/7nTItB
         Zbcy6YFftApQMFRnJ4UcXbhw61TL/fXLfONJsWKm51XUa7X/H3YI2q2UJlIZ7ayLL30C
         AivA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PGV9hCcukbJXdjwikIPJCCJ7y0lm9gzp/mhGfIgz/V0=;
        b=MPE0sMCjnY9OwhCHZnorW27uq1FJGf1Q7Q2HOMvQInaqS/3jVHqZsXBNeaUS6E/ciV
         TyoprnboFZbzDIXBZZ87+7JsNHRfbg5gwJ2MVKO2463xCFZCu1jz2/qyJa2mF0XNDXI9
         tzh/FG594PaxfgclKSIqWt8tArupD+rHpa2uP9oMjp5/mKuf0hWi1PMiwXYn8EUWQlR5
         +KhXqDVKE4LhuxMnu6+MwkFaEo5Y2ixSbt+hLmYX/mjCGfOADWOhHzVYg392+8YllOVh
         75JcwJ1Rj61aV2GfpuZzAQLKASD1dsA1/2RDhi7X8BxFnxTplqsuiq3FX1xX5xM1dK/Z
         AN+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PGV9hCcukbJXdjwikIPJCCJ7y0lm9gzp/mhGfIgz/V0=;
        b=gjIVaxOIzzG90b5EVAfDBeQL4TIMGQ8tGFTtFzDEcuzQ5qhlyiA+0+rIEEBwGkIEAQ
         V8xUtuTtwqbYTrHQG01Hgy90HYpD9rYT3d+vNqhpKFpdbRDfUf/Dpfk+rw+qwDIPzDLb
         oC8pbqp5bkX1Ri7CNXGCVd+vPVEw+FF4hzA/ZGdQ/xdAljNDx8ejZPbUoULYjY4mlOWR
         vKacvgXP1iGmuutnclyKQE1+zi55DmEe/diZKW1uI0CBHnZG/F2QrgNJa7KZu1qRYTbY
         QoSa8w+LN80ee6wQ5gB6l+g3TLpFx5bbx2TJeKX+wGPekAsgn0Mtx/nn0j6Cqv5QbZVL
         e2ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUhQntLWD6YlLqq918ShOuOuwnNZZP+/fC/Hsh1tsIXoZHkmyFR
	rzqKwwHcLe9GkAmCC20AzKQ=
X-Google-Smtp-Source: APXvYqzf0CVX+V6b1wndR/2+gyfhgAf15vKP/+2p35Lmr1OIOqDZa191WidNhndTn+/KYm2Y5u4zew==
X-Received: by 2002:aca:ad11:: with SMTP id w17mr4852072oie.85.1578082758438;
        Fri, 03 Jan 2020 12:19:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60d0:: with SMTP id b16ls9990293otk.0.gmail; Fri, 03 Jan
 2020 12:19:18 -0800 (PST)
X-Received: by 2002:a05:6830:4b9:: with SMTP id l25mr102437471otd.266.1578082758083;
        Fri, 03 Jan 2020 12:19:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578082758; cv=none;
        d=google.com; s=arc-20160816;
        b=xoyumqdgzsh5DKTmVZmq9w5210hEXpyoA2yxaTQWB3J3sR37nGKflMfoiGVT9tJKJy
         dZndzND4g8nX9y2lIZUss7C3rxS0w+zVG8fpnwkiVmAVcy9uUFmA7js8J81zfUfswG2U
         Pv3KnjpmzDi2Oksb6D6lNhJbNAwXJZEsS8kbSG4ZFcbwZlieT0Is6BgKcjJb17MUUsWi
         JhDN4NPRmxAEsOqG3+hjijGKXPz0NnwyXjhKz//Huy3bGyvP3Sebm9gmRAhOzRR35EDM
         E6HIHgUG+p7n0TWbna4+7qHK6xbMnzQhmd3OC20HJB6E2T1TFfRe4VnxB7dS+tzSIeJS
         OVxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=40ACnQIUnpge54Cj+EODMXbGQ2AM0yGbootCDBdgIh0=;
        b=UCAxN0u1/ulHRosmO+v2KSYQ2/Qhowl1UoqDvYw+Ytvcd9An+i/a4X6cJA/af6IBJN
         U5GcTFtXBPQhjcs8akTztYM7ytEHeRTDxwCoMR+FhTHYlfIgkSsXLDtu+Decw3xML50L
         MZ8wquh8Q4zvARZsgCo4B91YrJJW8m+c8vHVDVNxMX3UWeXG+FbE8hd9GpAvU7TPy6qf
         VuvLjj5/klS7CzW49o+Q9Dc5ZQXGoE3KowCIrUGLX1tZPkTjnk4a23ZavNK6Ak6sZB/X
         JuY+kYyhAqErTi4xCUB+Daw/DBrVpmwLzvDFi1ly18Tpoks44ciZoLgme1LN3bPm/st+
         mfRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eVI94djE;
       spf=pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id e14si2016760otr.1.2020.01.03.12.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Jan 2020 12:19:18 -0800 (PST)
Received-SPF: pass (google.com: domain of westernunion.benin982@gmail.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 21so34756196qky.4
        for <kasan-dev@googlegroups.com>; Fri, 03 Jan 2020 12:19:18 -0800 (PST)
X-Received: by 2002:a05:620a:13e3:: with SMTP id h3mr71007663qkl.319.1578082757568;
 Fri, 03 Jan 2020 12:19:17 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:ac8:4410:0:0:0:0:0 with HTTP; Fri, 3 Jan 2020 12:19:16 -0800 (PST)
From: "Rev.Dr Emmanuel Okoye CEO Ecobank-benin" <westernunion.benin982@gmail.com>
Date: Fri, 3 Jan 2020 21:19:16 +0100
Message-ID: <CAP=nHBJveAobo1vTh+r90nvjmCNX5JA8OmKXRxq_g2-4tX+xaA@mail.gmail.com>
Subject: I promise you must be happy today, God has uplifted you and your
 family ok
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: westernunion.benin982@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=eVI94djE;       spf=pass
 (google.com: domain of westernunion.benin982@gmail.com designates
 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=westernunion.benin982@gmail.com;
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

Dear Friend

i hope all is well with you,if so, glory be to God almighty. I'm very
happy to inform you, about my success in getting payment funds under
the cooperation of a new partner from United States of
America.Presently I am in uk for investment projects with my own share
of the total sum. I didn't forget your past efforts. IMF finally
approved your compensation payment funds this morning by prepaid (ATM)
Debit card of US$12,500.000.00Million Dollars, Since you not received
this payment yet, I was not certified
but it is not your fault and not my fault, I hold nothing against
you.than bank official whom has been detaining the transfer in the
bank, trying to claim your funds by themselves.

Therefore, in appreciation of your effort I have raised an
International prepaid (ATM) Debit card of US$12,500.000.00 in your
favor as compensation to you.

Now, i want you to contact my Diplomatic Agent, His name is Mike Benz
on His  e-mail Address (mikebenz550@aol.com

ask Him to send the Prepaid (ATM) Debit card to you. Bear in mind that
the money is in Prepaid (ATM) Debit card, not cash, so you need to
send to him,
your full name
address  where the prepaid (ATM) Debit card will be delivered to you,
including your cell phone number. Finally, I left explicit
instructions with him, on how to send the (ATM CARD) to you.

The Prepaid (ATM) Debit card, will be send to you through my
Diplomatic Agent Mr. Mike Benz immediately you contact him. So contact
my Diplomatic Agent Mr. Mike Benz immediately you receive this letter.
Below is his contact information:

NAME : MIKE BENZ
EMAIL ADDRESS: mikebenz550@aol.com
Text Him, (256) 284-4886

Request for Delivery of the Prepaid (ATM) Debit card  to you today.
Note, please I have paid for the whole service fees for you, so the
only money you will send to my Diplomatic Agent Mr. Mike Benz is
$50.00 for your prepaid (ATM) Debit card DELIVERY FEE to your address
ok.
Let me know once you receive this Card at your address.
Best regards,
Rev.Dr, George Adadar

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP%3DnHBJveAobo1vTh%2Br90nvjmCNX5JA8OmKXRxq_g2-4tX%2BxaA%40mail.gmail.com.
