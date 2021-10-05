Return-Path: <kasan-dev+bncBDU7NT4XZYHRBKVX6CFAMGQESWHCSKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF9A1422257
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 11:32:27 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id z23-20020a4ad597000000b0029174f63d3esf14746721oos.18
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 02:32:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633426346; cv=pass;
        d=google.com; s=arc-20160816;
        b=zyHv/SdZCcX5VS7rxmDR0zt89uXoewOYbYK8eRi22bLPKA3lNi6hcrLYs/eIOdTO44
         iJ/zW1vybKAD9hHL10upll9Q8hdRYOefFfXhq2xm9L3kLtDssX3SBjyJHJLsLQpfMW8j
         nebS0I3wm+lfy/MAQ58eFf3BD9VnZA4E7Tz0P2DbQA6MQhxWz956ioUG6x0bpG5nqw0s
         7eAQAANBp6+Mf+kDVUOtBDv1iWlmpYc528K0irSkUvHVFGY4qkF1n7QhY/aX9L3mFJoR
         zaQVK+PN6torlNAd2pzm6r9vVR/f0rSDPq9pYR00kiWRSvXUiJ7Osf25qdOI6N2o1gdN
         8rgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=FdAVKHeEPuLyPkyPPjvndHpzXc0vq8+uf08DuAyNtz4=;
        b=MR474ARnMaWQeUMDuT8fPje7tgqUhsbhlWmiqcQP7PUF4Au6wnIwp1qBiQaXEsL1fU
         hYWnb4JO54AkqJVvmMg+o+kJYGQ9p5QAAStm3UleUNhGe6H+D99wUgYJ6xM8/Wr1lgwU
         6ceKHjOrO325XYCudcGZotDC+xa/ooxsv3q9vSGjSdin/UU29PUCWZOZ93YiDguuPbGh
         AzRif8L4QKXdoYPiihWZFKTVbW5z20wK5Sb27HEX9JD6w8pFwJ/A05kWW2C92xViTK0B
         3BX7SMrJNDdVSqtWXtTiCRMpBG1qJknfnrelBTvWEjSMNg7xC56v6tpX9iAtYBrB6RHY
         fNqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FezTBwUw;
       spf=pass (google.com: domain of tmouhamed283@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=tmouhamed283@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FdAVKHeEPuLyPkyPPjvndHpzXc0vq8+uf08DuAyNtz4=;
        b=rQTMCFAMOaRmkTCEFIcfmOb0oLEHZkP2pJC0x91BWyQH96sZm0iCreCklx8BPPgs7I
         ecKwhMuJFe4QzMLdY6loe/6Hd1SZWVcv7AAEf/1AsccQ+CVnHoS9oKtya2lq/moNhPgF
         3chRmOXj4yn1Nly/TzqZhIm2KBlVbubu0ukCgVOWTWvtKNO1wBoGgahoGbuPCJdGQOno
         1Owu7QxFrsR9qpCpJAHcSqBUqm40M0Ub/Z4H4WLk0I2/4RlRmpcZbXgdaXfAcDgFYe+k
         6JCRncsX9T6deUoiI7HltpxVq2kueI1W7gkxfX8ZU+mPnFllciR19rDkZgU3e/m45CDg
         qXeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FdAVKHeEPuLyPkyPPjvndHpzXc0vq8+uf08DuAyNtz4=;
        b=nswr+hDuXlsfF1TVIPtj/ZA8SrW1QSIRVb7GIjtAcMcPp2ls3uqvG6IMFcyBeI/CKe
         WUNuG/grL+gQfKZ/Sqm8JkKEB3tm+tp2Z7mMw8Cj6HMkzG371vtcCL82M46/voZcEvsv
         BOceWTtqzZJtNgXzqN/l01RJR/0MsjrVxgUlQAq7gF0EMxVPNxsmxP5YjrdEJZRm0kbv
         wQOD0DzDUr0ComnxJKSNwUYqlgLJDj17ogRWTcFfPsU0GXCmz+YxSAGfgkiUk6oVxV+6
         AIkSXXEf/y+1T+6iN63yRbP08Wqa41hGD+FG+iuyCokW4NCxxyzLiqhRrXVZed2UkAaq
         nS0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FdAVKHeEPuLyPkyPPjvndHpzXc0vq8+uf08DuAyNtz4=;
        b=sDMUtcadBkAlOy/k97+ZIAzjhpvgesL9EItCdWf0O7WYWVnLsTBvFqrKXy4qlP1fy2
         AyOQyiPwKIkB/XiKfFKaOnanMQckAlkxFeho+sy5YAI7VPAsQMiBKYnyiS/mcafiGort
         qBHItxUMIKC/P9W1jsWCEladcuQ5VJOJc7Ol1a5Y08UGcm3IB3SRTgVKoisMy0JR/nhu
         0IFRFRyZjE7mOBFFQ63wK1Z9ofaXfmHEsrMtElk7hdB/Vy6JmsNcb3UyNFdp0keV+600
         L13J9W/VcR2NvPeskU2lx/py03u7hjkM8AL3GTeehK88XmFC+t+PCHhovgJrA/6MwQu/
         3sUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306Bmd9khPNmxc65oAn50xj84A7HqZSY1z5hxVouL6Mm908lkYF
	WhbNuE/CVIyFq0O3O/w/GFI=
X-Google-Smtp-Source: ABdhPJzkBowzBFTCOtm7ab6E9U7JIVn6DOP9HFnMuodENG09kXAoPlWxzVLGDZTYdStPpU3htWHptQ==
X-Received: by 2002:a4a:eac6:: with SMTP id s6mr12507012ooh.42.1633426346725;
        Tue, 05 Oct 2021 02:32:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:df56:: with SMTP id w83ls3756032oig.3.gmail; Tue, 05 Oct
 2021 02:32:26 -0700 (PDT)
X-Received: by 2002:aca:3110:: with SMTP id x16mr1712463oix.64.1633426346424;
        Tue, 05 Oct 2021 02:32:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633426346; cv=none;
        d=google.com; s=arc-20160816;
        b=i3aqe0MLKDEGxZp5cgjlPmU6FW1bk7bN4xp0YkQQSsI3X2i464miYAdS2wsVdyiDR5
         /GBSPAemDnsXlgIrijeNopOrlD6rJZePhijMGso9sGpOltKjx5JEHAXgbq2qb2ic69yW
         KlC2eiDf94jAOPQxIXft71g/6RNFo9lex2eclWbtNQc11bDPP1c1AA2XJYiRCjxaRiw4
         i7MoL4MQ3ATPEZqPBbp3WfB5MCvcK5uCMJBXf1wG7CJY0xJJWMX5EId8QC4mwKvxQMSk
         A32pGnYWgV6hYVqnv+BmX1UPrNXeBYqxW6wCNvXUUfextcV4UmJDT798ADXGgRfhPwuM
         pm0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=GeYDH8knl2f0TBi72al7YsahDgzp54CWmZc4m6NIc6M=;
        b=mmdY5rhzSu5PvkVoQxzyfhJvBE/kBsUrJWoBp3zx3WIgnslEHu0LUKvAFURL6/CINH
         4N5Ay6JvLZZmjuq0kTygPcMAWhg1ubyHkQxogMam3fYikZIv2LjpWd0fgKz8+tGircrq
         TAbxOec7TiNDCdWhrbZbMYVYkAskuLCuIWXPk/jR337q0yg5JGAWd9gw00WE4vleYbJy
         cxoWiwNjQKsJGx6bcQn5oIuE26fQSqOOKWOBHM48uDn0aX7LO+y/bFLE9kRsydG0RieG
         PNsNUx+0qkqoeZSfVSuoi4e83AmkhjhK1mj/eMaSWTFWFeLfLcPwo5Ve4XBFxKYAIAav
         QHpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=FezTBwUw;
       spf=pass (google.com: domain of tmouhamed283@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=tmouhamed283@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id bi42si2222294oib.4.2021.10.05.02.32.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 02:32:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of tmouhamed283@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id w2so3383992uau.10
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 02:32:26 -0700 (PDT)
X-Received: by 2002:ab0:2095:: with SMTP id r21mr6917945uak.55.1633426345840;
 Tue, 05 Oct 2021 02:32:25 -0700 (PDT)
MIME-Version: 1.0
From: Traore Mouhamed <anyiarinze44@gmail.com>
Date: Tue, 5 Oct 2021 09:31:53 +0000
Message-ID: <CAO2Umj0E0DtUVSMy21ZKzYzAvc-CzRtNOe580jX3jv+xNXZFQA@mail.gmail.com>
Subject: =?UTF-8?Q?Warm_Greetings=2C_I_sent_this_letter_to_you_a_month_ag?=
	=?UTF-8?Q?o=2C_but_I=E2=80=99m_not_sure_you_received_it_because_I_haven=E2=80=99t_go?=
	=?UTF-8?Q?tten_any_response_from_you_which_is_why_I_am_resending_it_ag?=
	=?UTF-8?Q?ain=2E_I_am_Barrister_Anyi_Arinze_personal_lawyer_to_my_deceas?=
	=?UTF-8?Q?ed_client_before_his_untimely_death_with_family=2C_I_received_?=
	=?UTF-8?Q?a_mandate_from_his_bank_to_provide_=2F_present_close_relatives?=
	=?UTF-8?Q?_of_his_fund_amount_worth_fourteen_million_dollars=2C_I_contac?=
	=?UTF-8?Q?ted_you_after_an_unsuccessful_attempt_to_find_a_relative_of_?=
	=?UTF-8?Q?my_late_customer=2C_I_decided_to_contact_you_because_he_has_th?=
	=?UTF-8?Q?e_same_last_name_with_you=2E_Please_contact_me_for_further_inf?=
	=?UTF-8?Q?ormation=3A_Yours_sincerely=2C_Anyi_Arinze_Legal_practitioner_=2F_?=
	=?UTF-8?Q?Advocates=2E?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000001c54fd05cd97b5fe"
X-Original-Sender: anyiarinze44@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=FezTBwUw;       spf=pass
 (google.com: domain of tmouhamed283@gmail.com designates 2607:f8b0:4864:20::930
 as permitted sender) smtp.mailfrom=tmouhamed283@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000001c54fd05cd97b5fe
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAO2Umj0E0DtUVSMy21ZKzYzAvc-CzRtNOe580jX3jv%2BxNXZFQA%40mail.gmail.com.

--0000000000001c54fd05cd97b5fe
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAO2Umj0E0DtUVSMy21ZKzYzAvc-CzRtNOe580jX3jv%2BxNXZFQA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAO2Umj0E0DtUVSMy21ZKzYzAvc-CzRtNOe580jX3jv%2BxNX=
ZFQA%40mail.gmail.com</a>.<br />

--0000000000001c54fd05cd97b5fe--
